kpm的内存管理工具
支持
1.read,dump内存模块
2.显示所有进程以及pid
3.显示进程的maps

example:

ksud kpms control xpida "ps" 
ksud kpms control xpida "maps 11769"
ksud kpm control xpida "dump 11769 773720a000 77375dc000"
