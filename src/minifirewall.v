///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id: module_template 2008-03-13 gac1 $
//
// Module: module_template.v
// Project: NF2.1
// Description: defines a module for the user data path
//
///////////////////////////////////////////////////////////////////////////////
`timescale 1ns/1ps

module minifirewall
   #(
      parameter DATA_WIDTH = 64,
      parameter CTRL_WIDTH = DATA_WIDTH/8,
      parameter SRAM_ADDR_WIDTH = 19,
      parameter SRAM_DATA_WIDTH = DATA_WIDTH+CTRL_WIDTH,
      parameter UDP_REG_SRC_WIDTH = 2
   )
   (
      input  [DATA_WIDTH-1:0]             in_data,
      input  [CTRL_WIDTH-1:0]             in_ctrl,
      input                               in_wr,
      output                              in_rdy,

      output reg [DATA_WIDTH-1:0]         out_data,
      output reg [CTRL_WIDTH-1:0]         out_ctrl,
      output reg                          out_wr,
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

      output reg                          rd_0_req,
      output reg [19-1:0]                 rd_0_addr,
      input [DATA_WIDTH-1:0]              rd_0_data,
      input                               rd_0_ack,
      input                               rd_0_vld,

      output reg                          wr_0_req,
      output reg [19-1:0]                 wr_0_addr,
      output reg [DATA_WIDTH-1:0]         wr_0_data,
      input                               wr_0_ack,

      // misc
      input                                reset,
      input                                clk
   );

   // Define the log2 function
   `LOG2_FUNC

   //------------------------- Signals-------------------------------
   
   localparam                    SKIP_HDR =1;
   localparam                    WORD2_CHECK_IPV4 =2;
   localparam                    WORD3_CHECK_TCP =3;
   localparam                    WORD4_IP_ADDR =4;
   localparam                    WORD5_TCP_PORT =5;
   localparam                    CONSULTA_REGRAS = 6;
   localparam                    VERIFICA_PORTA = 7;
   localparam                    PAYLOAD =8;
   localparam                    CONSULTA_FALSO = 9;
   localparam                    ENVIA_WORDS_1_4 = 10;

   localparam ICMP        = 'h01;
   localparam TCP        = 'h06;
   localparam UDP        = 'h11;
   localparam SCTP        = 'h84;

   wire [DATA_WIDTH-1:0]         in_fifo_data;
   wire [CTRL_WIDTH-1:0]         in_fifo_ctrl;

   wire                          in_fifo_nearly_full;
   wire                          in_fifo_empty;
   reg                           in_fifo_rd_en;

   reg [3:0]                     state, state_next;
      
   reg                           wr_0_req_next, rd_0_req_next;
   reg [DATA_WIDTH-1:0]          wr_0_data_next;
 
   reg [SRAM_ADDR_WIDTH-1:0]     wr_0_addr_next, rd_0_addr_next;

   reg [31:0]                    num_TCP, num_TCP_next;

   reg [15:0]                    dst_port, dst_port_next;
   reg [15:0]                    src_port, src_port_next;
   reg                           drop, drop_next;

   reg [CTRL_WIDTH+DATA_WIDTH-1:0]   word1,word2,word3,word4;
   reg [CTRL_WIDTH+DATA_WIDTH-1:0]   word1_next,word2_next,word3_next,word4_next;

   reg [2:0]                     word_saved, word_saved_next;
   //------------------------- Local assignments -------------------------------

   assign in_rdy     = !in_fifo_nearly_full;
   //assign out_data   = in_fifo_data;
   //assign out_ctrl   = in_fifo_ctrl;

   //------------------------- Modules-------------------------------

   fallthrough_small_fifo_old #(
      .WIDTH(CTRL_WIDTH+DATA_WIDTH),
      .MAX_DEPTH_BITS(3)
   ) input_fifo (
      .din           ({in_ctrl, in_data}),   // Data in
      .wr_en         (in_wr),                // Write enable
      .rd_en         (in_fifo_rd_en),        // Read the next word
      .dout          ({in_fifo_ctrl, in_fifo_data}),
      .full          (),
      .nearly_full   (in_fifo_nearly_full),
      //.prog_full     (),
      .empty         (in_fifo_empty),
      .reset         (reset),
      .clk           (clk)
   );

   generic_regs
   #(
      .UDP_REG_SRC_WIDTH   (UDP_REG_SRC_WIDTH),
      .TAG                 (0),                 // Tag -- eg. MODULE_TAG
      .REG_ADDR_WIDTH      (1),                 // Width of block addresses -- eg. MODULE_REG_ADDR_WIDTH
      .NUM_COUNTERS        (0),                 // Number of counters
      .NUM_SOFTWARE_REGS   (0),                 // Number of sw regs
      //.NUM_SOFTWARE_REGS   (0),                 // Number of sw regs
      .NUM_HARDWARE_REGS   (0)                  // Number of hw regs
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
      //.software_regs    ({endereco19_porta13}),
      .software_regs    (),

      // --- HW regs interface
      .hardware_regs    (),

      .clk              (clk),
      .reset            (reset)
    );

   //------------------------- Logic-------------------------------

   always @(*) begin
      // Default values
      out_data   = in_fifo_data;
      out_ctrl   = in_fifo_ctrl;
      in_fifo_rd_en = 0;
      out_wr = 0;

      rd_0_req_next = 0;
      wr_0_req_next = 0;

      state_next = state;
      
      num_TCP = num_TCP_next;

      wr_0_req_next = 0;
      wr_0_data_next = wr_0_data;
      wr_0_addr_next = wr_0_addr;

      rd_0_req_next = 0;
      rd_0_addr_next = rd_0_addr;

      dst_port_next = dst_port;
      src_port_next = src_port;
      drop_next = drop;

      //early data words
      word1_next = word1;
      word2_next = word2;
      word3_next = word3;
      word4_next = word4;
      word_saved_next = word_saved;

      case(state)
      SKIP_HDR: begin
         if (!in_fifo_empty && out_rdy) begin
            //out_wr = 1;
            in_fifo_rd_en = 1;
            if(in_fifo_ctrl == 'h0) begin
               state_next = WORD2_CHECK_IPV4;
               word1_next = {in_fifo_ctrl,in_fifo_data};
               word_saved_next = word_saved + 'h1;
               //state_next = PAYLOAD;
            end
            else begin
               out_wr = 1;
               state_next = SKIP_HDR;
            end
         end
         else
            state_next = SKIP_HDR;
      end
      WORD2_CHECK_IPV4: begin
         $display("WORD2: %h\n",word_saved);
         $display("CPCI_NF2_DATA: %d, ADDR: %d\n",`CPCI_NF2_DATA_WIDTH,`CPCI_NF2_ADDR_WIDTH);
         if (!in_fifo_empty && out_rdy) begin
            //out_wr = 1;
            if(in_fifo_data[15:12] != 4'h4) begin
               {out_ctrl,out_data} = word1;
               out_wr = 1;
               in_fifo_rd_en = 0;
               state_next = PAYLOAD;
            end
            else begin
               word2_next = {in_fifo_ctrl,in_fifo_data};
               word_saved_next = word_saved + 'h1;
               state_next = WORD3_CHECK_TCP;
               in_fifo_rd_en = 1;
            end
         end
         else
            state_next = WORD2_CHECK_IPV4;
      end
      WORD3_CHECK_TCP: begin
         $display("WORD3\n");
         $display("TTL: %d, PROTO: %d\n",in_fifo_data[15:8],in_fifo_data[7:0]);
         if (!in_fifo_empty && out_rdy) begin
            //out_wr = 1;
            case(in_fifo_data[7:0]) //protocolo
               TCP: begin
                  $display("NEWTCP\n");
                  in_fifo_rd_en = 1;
                  num_TCP_next = num_TCP + 'h1;
                  word3_next = {in_fifo_ctrl,in_fifo_data};
                  word_saved_next = word_saved + 'h1;
                  state_next = WORD4_IP_ADDR;
               end
               default: begin
                  $display("NAOTCP\n");
                  in_fifo_rd_en = 0;
                  out_wr = 1;
                  {out_ctrl,out_data} = word1;
               //decrement because word1 is already forward
                  word_saved_next = word_saved - 'h1;
               //word_saved equal 1 sends word4, so we copy here   
                  word4_next = word2;
                  state_next = ENVIA_WORDS_1_4;
               end
            endcase
         end
         else
            state_next = WORD3_CHECK_TCP;
      end
      WORD4_IP_ADDR: begin
         $display("WORD4: %d\n", in_fifo_data[31:16]);
         $display("IP: %d:%d:%d:%d\n",in_fifo_data[47:40],in_fifo_data[39:32],in_fifo_data[31:24],in_fifo_data[23:16]);
         if (!in_fifo_empty && out_rdy) begin
            in_fifo_rd_en = 1;
            //out_wr = 1;
            word4_next = {in_fifo_ctrl,in_fifo_data};
            word_saved_next = word_saved + 'h1;
            state_next = WORD5_TCP_PORT;
         end
         else
            state_next = WORD4_IP_ADDR;
      end
      WORD5_TCP_PORT: begin
         $display("WORD5\n");
         $display("PORTA: %d, %d\n",in_fifo_data[47:32],in_fifo_data[31:16]);
         if (!in_fifo_empty && out_rdy) begin
            //out_wr = 1;
            //in_fifo_rd_en = 1;
            dst_port_next = in_fifo_data[31:16];
            src_port_next = in_fifo_data[47:32];
            //state_next = PAYLOAD;
            state_next = CONSULTA_REGRAS;
            //synthesis translate_off
            //state_next = CONSULTA_FALSO;
            //synthesis translate_on
         end
         else
            state_next = WORD5_TCP_PORT;
      end
      CONSULTA_FALSO: begin
         $display("CONSULTA_FALSO. DSTPORT: %d, SRCPORT: %d\n",dst_port,src_port);
         /*if((dst_port >=80 && dst_port < 95) || 
               (dst_port >=1010 && dst_port < 1025)) begin*/
         //between 1010 and 1060 there are 50 pkts that will be dropped
         if (dst_port >= 1010 && dst_port < 1060) begin
            drop_next = 1;
            state_next = PAYLOAD;
            $display("REJECTED\n");
         end
         else begin
            drop_next = 0;
            state_next = ENVIA_WORDS_1_4;
            $display("ACCEPTED\n");
         end
      end
      CONSULTA_REGRAS: begin
         $display("CONSULTA REGRAS\n");
         rd_0_req_next = 1;
         rd_0_addr_next = 'h0;
         state_next = VERIFICA_PORTA;
      end
      VERIFICA_PORTA: begin
         $display("VERIFICA PORTA\n");
         //if (rd_0_ack) begin
         if (rd_0_vld) begin
            $display("dataread: %h\n",rd_0_data);
            if(rd_0_data[17:0] == dst_port) begin
               $display("REJECTED1\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else if(rd_0_data[35:18] == dst_port) begin
               $display("REJECTED2\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else if(rd_0_data[53:36] == dst_port) begin
               $display("REJECTED3\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else if(rd_0_data[71:54] == dst_port) begin
               $display("REJECTED4\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else begin
               $display("ACCEPTED\n");
               drop_next = 0;
               state_next = ENVIA_WORDS_1_4;
            end
         end
         else
            state_next = VERIFICA_PORTA;
      end
      ENVIA_WORDS_1_4: begin
         $display("ENVIA_WORDS_1_4: %h\n", word_saved);
         if (!in_fifo_empty && out_rdy) begin
            case(word_saved)
            1: begin
               out_wr = 1;
               out_ctrl = word4[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = word4[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS_1_4;
               word_saved_next = word_saved - 'h1;
            end
            2: begin
               out_wr = 1;
               out_ctrl = word3[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = word3[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS_1_4;
               word_saved_next = word_saved - 'h1;
            end
            3: begin
               out_wr = 1;
               out_ctrl = word2[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = word2[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS_1_4;
               word_saved_next = word_saved - 'h1;
            end
            4: begin
               out_wr = 1;
               out_ctrl = word1[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = word1[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS_1_4;
               word_saved_next = word_saved - 'h1;
            end
            default: begin
               out_wr = 1;
               in_fifo_rd_en = 1;
               state_next = PAYLOAD;
            end
            endcase
         end
         else
            state_next = ENVIA_WORDS_1_4;
      end
      PAYLOAD: begin
         $display("PAYLOAD\n");
         if (!in_fifo_empty && out_rdy) begin
            in_fifo_rd_en = 1;
            out_wr = 1;
            if(in_fifo_ctrl != 'h0) begin
               state_next = SKIP_HDR;
               drop_next = 0;
               word_saved_next = 'h0;
            end
            else begin
               if(drop) begin
                  //$display("DROPPED\n");
                  out_ctrl = 'h54; //Next module won't recognize pkt
               end
               else begin
                  //$display("NOTDROPPED\n");
                  out_ctrl   = in_fifo_ctrl;
               end
               state_next = PAYLOAD;
            end
         end
         else
            state_next = PAYLOAD;
      end
      endcase
   end

   always @(posedge clk) begin
      if(reset) begin
         wr_0_req <= 0;
         rd_0_req <= 0;
         state <= SKIP_HDR;
         num_TCP <= 0;
         drop <= 0;
         word_saved <= 0;
         dst_port <= 0;
         src_port <= 0;
      end
      else begin
         state <= state_next;
         // SRAM
         rd_0_req <= rd_0_req_next;
         rd_0_addr <= rd_0_addr_next;
         wr_0_req <= wr_0_req_next;
         wr_0_data <= wr_0_data_next;
         wr_0_addr <= wr_0_addr_next;
         dst_port <= dst_port_next;
         src_port <= src_port_next;
         drop <= drop_next;
         word_saved <= word_saved_next;
         word1 <= word1_next;
         word2 <= word2_next;
         word3 <= word3_next;
         word4 <= word4_next;
      end
   end

endmodule
