#!/bin/env python

from NFTest import *

phy2loop0 = ('../connections/conn', 'nf2c0')

nftest_init(sim_loop = [], hw_config = [phy2loop0])
nftest_start()
#nftest_fpga_reset()

for i in range(20):
   nftest_regwrite((reg_defines.SRAM_BASE_ADDR()+(i<<2)),i<<4)
   #print 'addr: %x\n' %((reg_defines.SRAM_BASE_ADDR()+(i<<2)))

for i in range(20):
   nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()+(i<<2)),i<<4)

#nftest_regwrite((reg_defines.SRAM_BASE_ADDR()),(0xdead))
#nftest_regwrite((reg_defines.SRAM_BASE_ADDR()+2),(0xedad))
#nftest_regwrite((reg_defines.SRAM_BASE_ADDR()+4),(0xaedd))
#nftest_regwrite((reg_defines.SRAM_BASE_ADDR()+6),(0xdaed))
#print 'addr: %x\n' %((reg_defines.SRAM_BASE_ADDR()+(i<<2)))

#nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()),0xdaed)
#nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()+1),0xaedd)
#nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()+2),0xedad)
#nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()+3),0xdead)
#nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()),(0xdead<<54|0xedad<<36|0xaedd<<18|0xdaed))
#nftest_barrier()
nftest_finish()
