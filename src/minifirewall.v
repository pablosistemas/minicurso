///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id: preprocess 2008-03-13 gac1 $
//
// Module: preprocess.v
// Project: NF2.1
// Description: defines a module for the user data path
//
///////////////////////////////////////////////////////////////////////////////
//Utiliza duas fifos, sendo uma ainterface com módulo anterior e segunda
//empilha cinco primeiras palavras de pacotes TCP
`timescale 1ns/1ps

module simulacao
   #(
      parameter DATA_WIDTH = 64,
      parameter CTRL_WIDTH = DATA_WIDTH/8,
      parameter SRAM_ADDR_WIDTH = 18,
      parameter UDP_REG_SRC_WIDTH = 2
   )
   (
      input  [DATA_WIDTH-1:0]             in_data,
      input  [CTRL_WIDTH-1:0]             in_ctrl,
      input                               in_wr,
      output                              in_rdy,

      output reg [DATA_WIDTH-1:0]         out_data,
      output reg[CTRL_WIDTH-1:0]          out_ctrl,
      output                              out_wr,
      input                               out_rdy,

      // --- Register interface
      input                               reg_req_in,
      input                               reg_ack_in,
      input                               reg_rd_wr_L_in,
      input  [`UDP_REG_ADDR_WIDTH-1:0]    reg_addr_in,
      input  [`CPCI_NF2_DATA_WIDTH-1:0]   reg_data_in,
      input  [UDP_REG_SRC_WIDTH-1:0]      reg_src_in,

      output                              reg_req_out,
      output                              reg_ack_out,
      output                              reg_rd_wr_L_out,
      output  [`UDP_REG_ADDR_WIDTH-1:0]   reg_addr_out,
      output  [`CPCI_NF2_DATA_WIDTH-1:0]  reg_data_out,
      output  [UDP_REG_SRC_WIDTH-1:0]     reg_src_out,
   
      // --- SRAM controller
      output reg                          wr_0_req,
      output reg [SRAM_ADDR_WIDTH-1:0]    wr_0_addr,
      output reg [DATA_WIDTH-1:0]         wr_0_data,
      input                               wr_0_ack,

      output reg                          rd_0_req,
      output reg [SRAM_ADDR_WIDTH-1:0]    rd_0_addr,
      input [DATA_WIDTH-1:0]              rd_0_data,
      input                               rd_0_ack,
      input                               rd_0_vld,

      output reg  [SRAM_ADDR_WIDTH-1:0]   hash_0,
      output reg  [SRAM_ADDR_WIDTH-1:0]   hash_1,
      input                               data_proc,
      input                               ack_proc,
      output reg                          data_pkt,
      output reg                          ack_pkt,

      // misc
      input                                reset,
      input                                clk
   );

   // Define the log2 function
   `LOG2_FUNC

   parameter   CRC_ADDR_WIDTH = 19;

   //--------------------- Internal Parameter-------------------------
   localparam NUM_STATES = 16;

   localparam SKIP_HDR    = 1;
   localparam WORD2_CHECK_IPV4    = 2;
   localparam WORD3_CHECK_TCP    = 4;
   localparam WORD4_IP_ADDR    = 8;
   localparam WORD5_TCP_PORT    = 16;
   localparam WORD6_TCP_ACK    = 32;
   localparam HASH_FOR_ACK    = 64;
   localparam HASH_FOR_DATA    = 128;
   localparam TEMP    = 256;
   localparam LOOKUP_1ST_PORT = 512;
   localparam LOOKUP_2ND_PORT = 1024;
   localparam LOOKUP_3RD_PORT = 2048;
   localparam LOOKUP_4TH_PORT = 2**15;
   localparam TUPLE_FOR_ACK    = 4096;
   localparam TUPLE_FOR_DATA    = 8192;
   localparam PAYLOAD            = 16384;
   
   localparam ICMP        = 'h01;
   localparam TCP        = 'h06;
   localparam UDP        = 'h11;
   localparam SCTP        = 'h84;
   //------------------------- Signals-------------------------------

   wire [DATA_WIDTH-1:0]         in_fifo_data_dout;
   wire [CTRL_WIDTH-1:0]         in_fifo_ctrl_dout;

   wire [DATA_WIDTH-1:0]         pacote_data_dout;
   wire [CTRL_WIDTH-1:0]         pacote_ctrl_dout;

   wire                          in_fifo_nearly_full;
   wire                          in_fifo_empty;

   wire                          pacote_nearly_full;
   wire                          pacote_empty;

   reg                           in_fifo_rd_en;
   reg                           out_wr_int;

   reg [NUM_STATES-1:0]          state;
   reg [NUM_STATES-1:0]          state_next;

   reg[255:0]			            tuple_next;
   reg[255:0]			            tuple;

   reg[31:0]			            seqnum_next;
   reg[31:0]			            seqnum;

   reg[31:0]			            acknum_next;
   reg[31:0]			            acknum;

   reg[31:0]			            srcip_next;
   reg[31:0]			            srcip;

   reg[31:0]			            dstip_next;
   reg[31:0]			            dstip;

   reg[15:0]			            srcport_next;
   reg[15:0]			            srcport;

   reg[15:0]			            dstport_next;
   reg[15:0]			            dstport;

   reg[15:0]			            length_next;
   reg[15:0]			            length;

   reg[SRAM_ADDR_WIDTH-1:0]      hash_0_next;
   reg[SRAM_ADDR_WIDTH-1:0]		hash_1_next;

   reg                           datapkt;
   reg                           datapkt_next;

   reg                           isack;
   reg                           isack_next;

   reg                            data_pkt_next;
   reg                            ack_pkt_next;

   wire [31:0]                    num_pkts_gen;
   reg [31:0]                     num_pkts;
   reg [31:0]                     num_pkts_next;

   reg [31:0]                     num_TCP_pkts;
   reg [31:0]                     num_TCP_pkts_next;
   wire [31:0]                    num_TCP_pkts_gen;

   reg [31:0]                     num_ICMP_pkts;
   reg [31:0]                     num_ICMP_pkts_next;
   wire [31:0]                    num_ICMP_pkts_gen;

   reg [31:0]                     num_SCTP_pkts;
   reg [31:0]                     num_SCTP_pkts_next;
   wire [31:0]                    num_SCTP_pkts_gen;

   reg [31:0]                     num_UDP_pkts;
   reg [31:0]                     num_UDP_pkts_next;
   wire [31:0]                    num_UDP_pkts_gen;

   reg [31:0]                     num_ACK_pkts;
   reg [31:0]                     num_ACK_pkts_next;
   wire [31:0]                    num_ACK_pkts_gen;

   reg [31:0]                     num_escrita;
   reg [31:0]                     num_escrita_next;
   wire [31:0]                    num_escrita_gen;

   reg [31:0]                     num_leitura;
   reg [31:0]                     num_leitura_next;
   wire [31:0]                    num_leitura_gen;

   wire [31:0]                    tuple_PSRC_gen;
   wire [31:0]                    tuple_PDST_gen;
   wire [31:0]                    tuple_IPSRC_gen;
   wire [31:0]                    tuple_IPDST_gen;
   wire [31:0]                    tuple_ACKNUM_gen;
   
   // --- SRAM controller aux
   reg [SRAM_ADDR_WIDTH-1:0]      rd_0_addr_next;
   reg [DATA_WIDTH-1:0]           rd_0_data_next;
   reg                            rd_0_req_next;
   //------------------------- Local assignments -------------------------------

   assign in_rdy     = !in_fifo_nearly_full;
   assign out_wr     = out_wr_int;
   assign num_pkts_gen = num_pkts;
   assign num_TCP_pkts_gen = num_TCP_pkts;
   assign num_SCTP_pkts_gen = num_SCTP_pkts;
   assign num_UDP_pkts_gen = num_UDP_pkts;
   assign num_ICMP_pkts_gen = num_ICMP_pkts;
   assign num_ACK_pkts_gen = num_ACK_pkts;
   assign num_escrita_gen = num_escrita;
   assign num_leitura_gen = num_leitura;

   assign tuple_PSRC_gen = tuple[15:0];
   assign tuple_PDST_gen = tuple[31:16];
   assign tuple_IPSRC_gen = tuple[63:32];
   assign tuple_IPDST_gen = tuple[95:64];
   assign tuple_ACKNUM_gen = tuple[127:96];

   fallthrough_small_fifo #(
      .WIDTH(CTRL_WIDTH+DATA_WIDTH),
      .MAX_DEPTH_BITS(3)
   ) input_fifo (
      .din           ({in_ctrl, in_data}),   // Data in
      .wr_en         (in_wr),                // Write enable
      .rd_en         (in_fifo_rd_en),        // Read the next word
      .dout          ({in_fifo_ctrl_dout, in_fifo_data_dout}),
      .full          (),
      .nearly_full   (in_fifo_nearly_full),
      .prog_full     (),
      .empty         (in_fifo_empty),
      .reset         (reset),
      .clk           (clk)
   );

   generic_regs
   #(
      .UDP_REG_SRC_WIDTH   (UDP_REG_SRC_WIDTH),
      .TAG                 (`SIMULACAO_BLOCK_ADDR),                 // Tag -- eg. MODULE_TAG
      .REG_ADDR_WIDTH      (`SIMULACAO_REG_ADDR_WIDTH),                 // Width of block addresses -- eg. MODULE_REG_ADDR_WIDTH
      .NUM_COUNTERS        (0),                 // Number of counters
      .NUM_SOFTWARE_REGS   (0),                 // Number of sw regs
      .NUM_HARDWARE_REGS   (12)                  // Number of hw regs
   ) module_regs (
      .reg_req_in       (reg_req_in),
      .reg_ack_in       (reg_ack_in),
      .reg_rd_wr_L_in   (reg_rd_wr_L_in),
      .reg_addr_in      (reg_addr_in),
      .reg_data_in      (reg_data_in),
      .reg_src_in       (reg_src_in),

      .reg_req_out      (reg_req_out),
      .reg_ack_out      (reg_ack_out),
      .reg_rd_wr_L_out  (reg_rd_wr_L_out),
      .reg_addr_out     (reg_addr_out),
      .reg_data_out     (reg_data_out),
      .reg_src_out      (reg_src_out),

      // --- counters interface
      .counter_updates  (),
      .counter_decrement(),

      // --- SW regs interface
      .software_regs    (),

      // --- HW regs interface
      .hardware_regs    ({num_pkts_gen,num_TCP_pkts_gen,num_UDP_pkts_gen,num_ICMP_pkts_gen,num_ACK_pkts_gen,num_escrita_gen,num_leitura_gen,tuple_ACKNUM_gen,tuple_IPDST_gen,tuple_IPSRC_gen,tuple_PDST_gen,tuple_PSRC_gen}),

      .clk              (clk),
      .reset            (reset)
    );

   //------------------------- Logic-------------------------------

   always @(*) begin
      out_ctrl = in_fifo_ctrl_dout;
      out_data = in_fifo_data_dout;
      ////////////////////////////
      state_next = state;
      tuple_next = tuple;
      hash_0_next = hash_0;
      hash_1_next = hash_1;

      seqnum_next = seqnum;
      acknum_next = acknum;
      srcip_next = srcip;
      dstip_next = dstip;
      srcport_next = srcport;
      dstport_next = dstport;

      datapkt_next = datapkt;
      isack_next = isack;
      length_next = length;
      //////////////////////////// colocar if ("in_fifo_empty ...
      in_fifo_rd_en = 0; // = (!in_fifo_empty && out_rdy)
      out_wr_int = 0;

      data_pkt_next = data_pkt;
      ack_pkt_next = ack_pkt;
      num_pkts_next = num_pkts;
      num_ACK_pkts_next = num_ACK_pkts;
      num_TCP_pkts_next = num_TCP_pkts;
      num_ICMP_pkts_next = num_ICMP_pkts;
      num_UDP_pkts_next = num_UDP_pkts;
      num_SCTP_pkts_next = num_SCTP_pkts;
      num_escrita_next = num_escrita;
      num_leitura_next = num_leitura;
      
      case(state)
         // Espera por CTRL == 0 (Inicio do pacote)
         SKIP_HDR: begin
            //$display("SKIP HDR\n");
            if (!in_fifo_empty && out_rdy) begin
               out_wr_int = 1;
               in_fifo_rd_en = 1;
			      if(in_fifo_ctrl_dout == 'h0) begin
				      state_next = WORD2_CHECK_IPV4;
                  num_pkts_next = num_pkts_next+1;
			      end
		      end
	      end //SKIP_HEADER
         WORD2_CHECK_IPV4: begin
            $display("WORD2\n");
		      if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 1;
           	   in_fifo_rd_en = 1;
			      if(in_fifo_data_dout[15:12] != 4'h4) 
                  state_next = PAYLOAD;
               else begin
                  state_next = WORD3_CHECK_TCP;
               end
            end
         end 
         WORD3_CHECK_TCP: begin
            $display("WORD3\n");
            if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 1;
           	   in_fifo_rd_en = 1;
               case(in_fifo_data_dout[7:0]) //protocolo
                  ICMP: begin
                     num_ICMP_pkts_next = num_ICMP_pkts_next + 1;
                     state_next = PAYLOAD;
                  end
                  TCP: begin
                     num_TCP_pkts_next = num_TCP_pkts_next + 1;
                     $display("TCP: %03d, UDP: %03d, ICMP: %03d, SCTP: %03d\n", num_TCP_pkts_next,num_UDP_pkts_next,num_ICMP_pkts_next,num_SCTP_pkts_next);
                     length_next=in_fifo_data_dout[63:48]; //total_length
                     state_next = WORD4_IP_ADDR;
                  end
                  UDP: begin
                     num_UDP_pkts_next = num_UDP_pkts_next + 1;
                     state_next = PAYLOAD;
                  end
                  SCTP: begin
                     num_SCTP_pkts_next = num_SCTP_pkts_next + 1;
                     state_next = PAYLOAD;
                  end
                  default: begin
                     state_next = PAYLOAD;
                  end
               endcase
            end
         end 
         WORD4_IP_ADDR: begin
            $display("WORD4\n");
            if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 1;
           	   in_fifo_rd_en = 1;
               srcip_next = in_fifo_data_dout[47:16]; //srcIP
               dstip_next[31:16] = {in_fifo_data_dout[15:0]}; //dstIp1
               state_next = WORD5_TCP_PORT;
            end
         end  
         WORD5_TCP_PORT: begin
            $display("WORD5\n");
            if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 1;
           	   in_fifo_rd_en = 1;
               //tuple[15:0]=in_fifo_data_dout[47:32]; //SRC_PORT
               //tuple[31:16]=in_fifo_data_dout[31:16]; //DST_PORT
               //tuple_next[31:0]=in_fifo_data_dout[47:16]; //SRC+DST PORT
               //tuple_next[47:32]=in_fifo_data_dout[63:48]; //DST_IP PART II
               dstip_next[15:0] = in_fifo_data_dout[63:48]; //dstIp2
               srcport_next = in_fifo_data_dout[47:32]; //srcPort
               dstport_next = in_fifo_data_dout[31:16]; //dstPort
               seqnum_next[31:16] = in_fifo_data_dout[15:0]; //SEQ PART I
               state_next = PAYLOAD;
            end
         end 
         LOOKUP_1ST_PORT: begin
               rd_0_req_next = 1;
               rd_0_addr_next = 19'h1; 
         end
         WORD6_TCP_ACK: begin
            $display("WORD6\n");
            if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 1;
           	   in_fifo_rd_en = 1;
            end
         end
//before alteration, out_wr_int and in_fifo_rd_en was in 0 up to PAYLOAD
         TUPLE_FOR_ACK:  begin
            $display("TUPLEACK\n");
            if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 0;
           	   in_fifo_rd_en = 0;
               //inv{IDFlow}: src<>dst
               tuple_next[15:0]={(16){dstport}};
               tuple_next[31:16]={(16){srcport}};
               tuple_next[63:32]={(32){dstip}};
               tuple_next[95:64]={(32){srcip}};
               tuple_next[127:96]={(32){acknum}};
               tuple_next[255:128]={(256-128){1'b0}};

               state_next = HASH_FOR_ACK;
            end
         end
         TUPLE_FOR_DATA:  begin
            $display("TUPLEDATA\n");
            if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 0;
           	   in_fifo_rd_en = 0;
               //{IDFlow}: dst<>src, sequence=seq+length+1
               //tuple_next={{128'b0},(32){seqnum+length+1},(32){dstip},(32){srcip},(16){dstport},(16){srcport}};
               tuple_next[15:0]={(16){srcport}};
               tuple_next[31:16]={(16){dstport}};
               tuple_next[63:32]={(32){srcip}};
               tuple_next[95:64]={(32){dstip}};
               tuple_next[127:96]={(32){seqnum+length+1}};
               tuple_next[255:128]={(256-128){1'b0}};

               state_next = HASH_FOR_DATA;
            end
         end
         HASH_FOR_ACK:  begin
            $display("HASHACK\n");
            if (!in_fifo_empty && out_rdy) begin
               $display("ACK tuple: %h\n",tuple[127:0]);
           	   out_wr_int = 0;
           	   in_fifo_rd_en = 0;
               hash_0_next = {2'b0,crcf0(tuple, 256'h0)};
               hash_1_next = {1'b0,crcf1(tuple, 256'h0)}; 
               state_next = TEMP;
               ack_pkt_next = 1'b1;
               //ack_pkt = 1'b1;
            end
         end
         HASH_FOR_DATA:  begin
            $display("HASHDATA\n");
            if (!in_fifo_empty && out_rdy) begin
               $display("DATA tuple: %h\n",tuple[127:0]);
           	   out_wr_int = 0;
           	   in_fifo_rd_en = 0;
               hash_0_next = crcf0(tuple, 256'h0);
               hash_1_next = crcf1(tuple, 256'h0);
               state_next = TEMP;
               data_pkt_next = 1'b1;
            end
         end
         TEMP:  begin
            $display("TEMP\n");
            {data_pkt_next,ack_pkt_next} = 2'b0;
            if (!in_fifo_empty && out_rdy) begin
                  out_wr_int = 0;
                  in_fifo_rd_en = 0;
               if(data_proc||ack_proc) begin
                  $display("dataproc: %x\n", hash_0_next);
                  //{data_pkt_next,ack_pkt_next} = 2'b0;
                  //{data_pkt,ack_pkt} = 2'b0;
 //if packet is ack and data, after reading must be write operation
                  if(length > 0 && isack) begin
                     datapkt_next = 0;
                     isack_next = 0;
                     state_next = TUPLE_FOR_DATA;
                  end
                  else
                     state_next = PAYLOAD;
               end
               else 
                  state_next = TEMP;
            end
         end
		   PAYLOAD: begin
            $display("PAYLOAD\n");
		      if (!in_fifo_empty && out_rdy) begin
           	   out_wr_int = 1;
           	   in_fifo_rd_en = 1;
               hash_0_next = 0;
               hash_1_next = 0;
			      //CHECA POR FIM DO PACOTE
		   	   if(in_fifo_ctrl_dout != 'h0)
				      state_next = SKIP_HDR;
               else
				      state_next = PAYLOAD;
		      end
	      end //PAYLOAD
	   endcase //case(state)
   end //always

   always @(posedge clk) begin
	   if(reset) begin
      ////////////////////-Sram
         {data_pkt,ack_pkt} <= 2'b0;
      ////////////////////-Sram
		   state <= SKIP_HDR;
         tuple <= 256'h0;
         seqnum <= 32'h0;
         acknum <= 32'h0;
         hash_0 <= {{SRAM_ADDR_WIDTH}{1'b0}};
         hash_1 <= {{SRAM_ADDR_WIDTH}{1'b0}}; //24'h0;

         srcip <=32'h0;
         dstip <=32'h0;
         srcport <=16'h0;
         dstport <=16'h0;

         isack <= 0;
         datapkt <= 0;
         length <= 0;

         num_pkts <= 0;
         num_UDP_pkts <= 0;
         num_SCTP_pkts <= 0;
         num_ICMP_pkts <= 0;
         num_TCP_pkts <= 0;
         num_ACK_pkts <= 0;
         num_escrita <= 0;
         num_leitura <= 0;
	   end
	   else begin
         //if(state_next != SKIP_HDR) begin
            //$display("state_next: %d\n", 30'h3fff_ffff);
            //$display("fifo_data_dout: %h\n", in_fifo_data_dout);
            //$display("hash_0: %h, hash_1: %h\n", hash_0_next, hash_1_next);
         //end
         /////////////////--Sram
         //if(state_next == WORD4_IP_ADDR) begin
            //wr_0_req_aux <= 0;
            //$display("length: %d, %x\n", length_next,length_next);
         //end
         //else if(state_next == WORD5_TCP_PORT) begin
            //$display("src ip: %03d.%03d.%03d.%03d\n", srcip_next[31:24],srcip_next[23:16],srcip_next[15:8],srcip_next[7:0]);
         //end
         //else if(state_next == WORD6_TCP_ACK) begin
            //$display("dst ip: %03d.%03d.%03d.%03d\n", dstip_next[31:24],dstip_next[23:16],dstip_next[15:8],dstip_next[7:0]);
            //$display("dst port: %d, %x\n",dstport_next,dstport_next);
            //$display("src port: %d, %x\n",srcport_next,srcport_next);
         //end
         if(in_fifo_nearly_full)
            $display("in_fifo_nearly_full: %d\n",in_fifo_nearly_full);
         data_pkt <= data_pkt_next;
         ack_pkt <= ack_pkt_next;
		   state <= state_next;
         tuple <= tuple_next;

         seqnum <= seqnum_next;
         acknum <= acknum_next;
         srcip <= srcip_next;
         dstip <= dstip_next;
         srcport <= srcport_next;
         dstport <= dstport_next;

         hash_0 <= hash_0_next;
         hash_1 <= hash_1_next;
         isack <= isack_next;
         datapkt <= datapkt_next;
         length <= length_next;
         num_pkts <= num_pkts_next;
         num_TCP_pkts <= num_TCP_pkts_next;

         num_ICMP_pkts <= num_ICMP_pkts_next;
         num_UDP_pkts <= num_UDP_pkts_next;
         num_SCTP_pkts <= num_SCTP_pkts_next;
         num_ACK_pkts <= num_ACK_pkts_next;
         num_escrita <= num_escrita_next;
         num_leitura <= num_leitura_next;
	   end
   end
endmodule
