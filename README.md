# KPM 内存管理工具

## 工具概述：
1. **内存模块读取与转储**：使用物理内存地址读取和转储模块
2. **进程信息查看**：显示系统中所有进程及其 PID
3. **进程内存映射分析**：查看指定进程的内存映射信息

## 使用语法
```bash
ksud kpm control xpida [命令]
ksud kpms control xpida "ps" 
ksud kpms control xpida "maps 11769"
ksud kpm control xpida "dump 11769 773720a000 77375dc000"
