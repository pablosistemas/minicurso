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
      output reg [SRAM_ADDR_WIDTH-1:0]    rd_0_addr,
      input [DATA_WIDTH-1:0]              rd_0_data,
      input                               rd_0_ack,
      input                               rd_0_vld,

      output reg                          wr_0_req,
      output reg [SRAM_ADDR_WIDTH-1:0]    wr_0_addr,
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
   localparam                    CHECK_PORTS = 7;
   localparam                    ENVIA_WORDS = 8;
   localparam                    PAYLOAD =9;
   localparam                    SRAM_PORTS_ADDR = 'h0;
   localparam                    WORD1 = 4;
   localparam                    WORD2 = 3;
   localparam                    WORD3 = 2;
   localparam                    WORD4 = 1;
   localparam                    NUM_WORDS_SALVAS = 4;

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

   /*reg [CTRL_WIDTH+DATA_WIDTH-1:0]   words [0:NUM_WORDS_SALVAS-1];
   reg [CTRL_WIDTH+DATA_WIDTH-1:0]   words_next [0:NUM_WORDS_SALVAS-1];*/
   
   reg [CTRL_WIDTH+DATA_WIDTH-1:0]   primeira_palavra, segunda_palavra, terceira_palavra, quarta_palavra;
   reg [CTRL_WIDTH+DATA_WIDTH-1:0]   primeira_palavra_nxt, segunda_palavra_nxt, terceira_palavra_nxt, quarta_palavra_nxt;

   reg [2:0]                     word_saved, word_saved_next;

   wire [31:0]                   dport1, dport2, dport3, dport4;
   wire                          addr_good, tag_hit;

   //------------------------- Local assignments -------------------------------

   assign in_rdy     = !in_fifo_nearly_full;

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
      .TAG                 (`MINIFIREWALL_BLOCK_ADDR),                 // Tag -- eg. MODULE_TAG
      .REG_ADDR_WIDTH      (`MINIFIREWALL_REG_ADDR_WIDTH), // Width of block addresses -- eg. MODULE_REG_ADDR_WIDTH
      .NUM_COUNTERS        (0),                 // Number of counters
      .NUM_SOFTWARE_REGS   (4),                 // Number of sw regs
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
      .software_regs    ({dport1,dport2,dport3,dport4}),

      // --- HW regs interface
      .hardware_regs    (),

      .clk              (clk),
      .reset            (reset)
    );

   //------------------------- Logic-------------------------------
   //

   assign tag_hit = reg_addr_out[`UDP_REG_ADDR_WIDTH - 1:`MINIFIREWALL_REG_ADDR_WIDTH]==`MINIFIREWALL_BLOCK_ADDR;
   //assign addr_good = reg_addr_out[`MINIFIREWALL_REG_ADDR_WIDTH-1:0] >= `MINIFIREWALL_DPORT1 && reg_addr_out[`MINIFIREWALL_REG_ADDR_WIDTH] <= `MINIFIREWALL_DPORT4;
   assign addr_good = reg_addr_out >= `MINIFIREWALL_DPORT1 && reg_addr_out <= `MINIFIREWALL_DPORT4;

   always @(*) begin
      wr_0_data_next <= {dport4[15:0],dport3[15:0],dport2[15:0],dport1[15:0]};
      wr_0_addr_next <= 'h0;
      if(tag_hit && addr_good && reg_ack_out) begin
         wr_0_req_next <= 1;
         //$display("endereco: %x\n", reg_addr_out);
      end
      else
         wr_0_req_next <= 0;
      //synthesis translate_off
      if(wr_0_ack) 
         $display("GRAVADO\n");
      //synthesis translate_on
   end

   always @(*) begin
      // Default values
      out_data   = in_fifo_data;
      out_ctrl   = in_fifo_ctrl;
      in_fifo_rd_en = 0;
      out_wr = 0;

      rd_0_req_next = 0;

      state_next = state;
      
      num_TCP = num_TCP_next;

      rd_0_req_next = 0;
      rd_0_addr_next = rd_0_addr;

      dst_port_next = dst_port;
      src_port_next = src_port;
      drop_next = drop;

      /*words_next[0] = words[0];
      words_next[1] = words[1];
      words_next[2] = words[2];
      words_next[3] = words[3];*/
      word_saved_next = word_saved;

      primeira_palavra_nxt = primeira_palavra;
      segunda_palavra_nxt = segunda_palavra;
      terceira_palavra_nxt = terceira_palavra;
      quarta_palavra_nxt = quarta_palavra;

      case(state)
      SKIP_HDR: begin
         if (!in_fifo_empty && out_rdy) begin
            in_fifo_rd_en = 1;
            $display("DATACTRL: %x %x",in_fifo_data, in_fifo_ctrl);
            if(in_fifo_ctrl == 'h0) begin
               state_next = WORD2_CHECK_IPV4;
               primeira_palavra_nxt = {in_fifo_ctrl,in_fifo_data};
               //words_next[word_saved] = {in_fifo_ctrl,in_fifo_data};
               word_saved_next = word_saved + 'h1;
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
            if(in_fifo_data[15:12] != 4'h4) begin
            //se nao for ipv4 apenas encaminha o pacote
               word_saved_next = word_saved - 'h1;
               //{out_ctrl,out_data} = words[0]; //word1;
               {out_ctrl,out_data} = primeira_palavra; //word1;
               out_wr = 1;
               in_fifo_rd_en = 0;
               state_next = PAYLOAD;
            end
            else begin
               //words_next[word_saved] = {in_fifo_ctrl,in_fifo_data};
               segunda_palavra_nxt = {in_fifo_ctrl,in_fifo_data};
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
            case(in_fifo_data[7:0]) //protocolo
               TCP: begin
                  $display("NEWTCP\n");
                  in_fifo_rd_en = 1;
                  num_TCP_next = num_TCP + 'h1;
                  //decrementa TTL
                  //words_next[word_saved] = {in_fifo_ctrl,in_fifo_data[63:16],in_fifo_data[15:8]-8'h1,in_fifo_data[7:0]};
                  terceira_palavra_nxt = {in_fifo_ctrl,in_fifo_data[63:16],in_fifo_data[15:8]-8'h1,in_fifo_data[7:0]};
                  word_saved_next = word_saved + 'h1;
                  state_next = WORD4_IP_ADDR;
               end
               default: begin
                  $display("NAOTCP\n");
                  in_fifo_rd_en = 0;
                  out_wr = 1;
                  //{out_ctrl,out_data} = words[0]; //word1;
                  {out_ctrl,out_data} = primeira_palavra;
               //decrementa pq ja enviamos a 1ª palavra
                  word_saved_next = word_saved - 'h1;
               //4ª word<=2ª para aproveitar estado de ENVIA_WORDS   
                  //words_next[3] = words[1];
                  quarta_palavra_nxt = segunda_palavra;
                  state_next = ENVIA_WORDS;
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
            //words_next[word_saved] = {in_fifo_ctrl,in_fifo_data[63:48]+16'h100,in_fifo_data[47:0]};
            quarta_palavra_nxt = {in_fifo_ctrl,in_fifo_data[63:48]+16'h100,in_fifo_data[47:0]};
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
            dst_port_next = in_fifo_data[31:16];
            src_port_next = in_fifo_data[47:32];
            state_next = CONSULTA_REGRAS;
         end
         else
            state_next = WORD5_TCP_PORT;
      end
      CONSULTA_REGRAS: begin
         $display("CONSULTA REGRAS\n");
         rd_0_req_next = 1;
         rd_0_addr_next = SRAM_PORTS_ADDR;
         state_next = CHECK_PORTS;
      end
      CHECK_PORTS: begin
         $display("VERIFICA PORTA\n");
         if (rd_0_vld) begin
            $display("dataread: %h\n",rd_0_data);
            if(rd_0_data[15:0] == dst_port) begin
               $display("REJECTED1\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else if(rd_0_data[31:16] == dst_port) begin
               $display("REJECTED2\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else if(rd_0_data[47:32] == dst_port) begin
               $display("REJECTED3\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else if(rd_0_data[63:48] == dst_port) begin
               $display("REJECTED4\n");
               drop_next = 1;
               state_next = PAYLOAD;
            end
            else begin
               $display("ACCEPTED\n");
               drop_next = 0;
               state_next = ENVIA_WORDS;
            end
         end
         else
            state_next = CHECK_PORTS;
      end
      ENVIA_WORDS: begin
         $display("ENVIA_WORDS: %h\n", word_saved);
         if (!in_fifo_empty && out_rdy) begin
            case(word_saved)
            WORD4: begin
               out_wr = 1;
               //out_ctrl = words[3][CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               //out_data = words[3][DATA_WIDTH-1:0];
               out_ctrl = quarta_palavra[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = quarta_palavra[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS;
               word_saved_next = word_saved - 'h1;
            end
            WORD3: begin
               out_wr = 1;
               /*out_ctrl = words[2][CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = words[2][DATA_WIDTH-1:0];*/
               out_ctrl = terceira_palavra[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = terceira_palavra[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS;
               word_saved_next = word_saved - 'h1;
            end
            WORD2: begin
               out_wr = 1;
               out_ctrl = segunda_palavra[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = segunda_palavra[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS;
               word_saved_next = word_saved - 'h1;
            end
            WORD1: begin
               out_wr = 1;
               out_ctrl = primeira_palavra[CTRL_WIDTH+DATA_WIDTH-1:DATA_WIDTH];
               out_data = primeira_palavra[DATA_WIDTH-1:0];
               state_next = ENVIA_WORDS;
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
            state_next = ENVIA_WORDS;
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
                  out_ctrl = 'h42; //Next module won't recognize pkt
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
         wr_0_data <= wr_0_data_next;
         wr_0_addr <= wr_0_addr_next;
         wr_0_req <= wr_0_req_next;

         dst_port <= dst_port_next;
         src_port <= src_port_next;
         drop <= drop_next;
         word_saved <= word_saved_next;
         /*word1 <= word1_next;
         word2 <= word2_next;
         word3 <= word3_next;
         word4 <= word4_next;*/
         /*words[0] <= words_next[0];
         words[1] <= words_next[1];
         words[2] <= words_next[2];
         words[3] <= words_next[3];*/
         primeira_palavra <= primeira_palavra_nxt;
         segunda_palavra <= segunda_palavra_nxt;
         terceira_palavra <= terceira_palavra_nxt;
         quarta_palavra <= quarta_palavra_nxt;
      end
   end

endmodule
