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
      parameter UDP_REG_SRC_WIDTH = 2
   )
   (
      input  [DATA_WIDTH-1:0]             in_data,
      input  [CTRL_WIDTH-1:0]             in_ctrl,
      input                               in_wr,
      output                              in_rdy,

      output [DATA_WIDTH-1:0]             out_data,
      output [CTRL_WIDTH-1:0]             out_ctrl,
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

      output reg                          rd_0_req,
      output reg [19-1:0]                 rd_0_addr,
      input [DATA_WIDTH-1:0]              rd_0_data,
      input                               rd_0_ack,
      input                               rd_0_vld,

      output reg                          wr_0_req,
      output reg [19-1:0]                 wr_0_addr,
      input [DATA_WIDTH-1:0]              wr_0_data,
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
   localparam                    PAYLOAD =6;

   wire [DATA_WIDTH-1:0]         in_fifo_data;
   wire [CTRL_WIDTH-1:0]         in_fifo_ctrl;

   wire [DATA_WIDTH-1:0]         out_fifo_data;
   wire [CTRL_WIDTH-1:0]         out_fifo_ctrl;

   wire                          in_fifo_nearly_full;
   wire                          in_fifo_empty;

   wire                          out_fifo_nearly_full;
   wire                          out_fifo_empty;

   reg                           in_fifo_rd_en;

   wire                          out_fifo_rd_en;

   reg                           out_wr_int, out_next_module;

   reg [2:0]                     state, state_next;
      
   reg                          wr_0_req_next, rd_0_req_next;
   //------------------------- Local assignments -------------------------------

   assign in_rdy     = !in_fifo_nearly_full;
   //assign out_wr     = out_wr_int;
   assign out_wr     = !out_fifo_empty;
   assign out_fifo_rd_en = !out_fifo_empty; 
  /* assign out_data   = in_fifo_data;
   assign out_ctrl   = in_fifo_ctrl;*/
   assign out_data   = out_fifo_data;
   assign out_ctrl   = out_fifo_ctrl;


   //------------------------- Modules-------------------------------

   fallthrough_small_fifo #(
      .WIDTH(CTRL_WIDTH+DATA_WIDTH),
      .MAX_DEPTH_BITS(2)
   ) input_fifo (
      .din           ({in_ctrl, in_data}),   // Data in
      .wr_en         (in_wr),                // Write enable
      .rd_en         (in_fifo_rd_en),        // Read the next word
      .dout          ({in_fifo_ctrl, in_fifo_data}),
      .full          (),
      .nearly_full   (in_fifo_nearly_full),
      .prog_full     (),
      .empty         (in_fifo_empty),
      .reset         (reset),
      .clk           (clk)
   );

   fallthrough_small_fifo #(
      .WIDTH(CTRL_WIDTH+DATA_WIDTH),
      .MAX_DEPTH_BITS(2)
   ) output_fifo (
      .din           ({in_fifo_ctrl, in_fifo_data}),   // Data in
      .wr_en         (out_wr_int),                // Write enable
      .rd_en         (out_fifo_rd_en),        // Read the next word
      .dout          ({out_fifo_ctrl, out_fifo_data}),
      .full          (),
      .nearly_full   (out_fifo_nearly_full),
      .prog_full     (),
      .empty         (out_fifo_empty),
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
      .software_regs    (),

      // --- HW regs interface
      .hardware_regs    (),

      .clk              (clk),
      .reset            (reset)
    );

   //------------------------- Logic-------------------------------

   always @(*) begin
      // Default values
      out_wr_int = 0;
      in_fifo_rd_en = 0;

      rd_0_req_next = 0;
      wr_0_req_next = 0;

      state_next = state;

      case(state)
      SKIP_HDR: begin
         if (!in_fifo_empty && out_rdy) begin
            out_wr_int = 1;
            in_fifo_rd_en = 1;
            if(in_fifo_ctrl == 'h0) begin
               state_next = PAYLOAD;
               $display("novopacote\n");
            end
            else
               state_next = SKIP_HDR;
         end
      end
      WORD2_CHECK_IPV4: begin
         if (!in_fifo_empty && out_rdy) begin
            out_wr_int = 1;
            in_fifo_rd_en = 1;
         end
      end
      WORD3_CHECK_TCP: begin
         if (!in_fifo_empty && out_rdy) begin
            out_wr_int = 1;
            in_fifo_rd_en = 1;
         end
      end
      WORD4_IP_ADDR: begin
         if (!in_fifo_empty && out_rdy) begin
            out_wr_int = 1;
            in_fifo_rd_en = 1;
         end
      end
      WORD5_TCP_PORT: begin
         if (!in_fifo_empty && out_rdy) begin
            out_wr_int = 1;
            in_fifo_rd_en = 1;
         end
      end
      PAYLOAD: begin
         if (!in_fifo_empty && out_rdy) begin
            out_wr_int = 1;
            in_fifo_rd_en = 1;
            if(in_fifo_ctrl!= 'h0)
               state_next = SKIP_HDR;
            else
               state_next = PAYLOAD;
         end
      end
      endcase
   end

   always @(posedge clk) begin
      if(reset) begin
         wr_0_req <= 0;
         rd_0_req <= 0;
         state <= 1;
      end
      else begin
         $display("modificado\n");
         state <= state_next;
         rd_0_req <= rd_0_req_next;
         wr_0_req <= wr_0_req_next;
      end
   end

endmodule