# TrafficGathering

## 简介

数控系统安全态势感知与分析系统-后端-流量收集与转发子系统。

从指定的网卡中监听数据包，并将其转发到消息队列中，供其他模块使用。

**NOTE：每个流量获取模块务必使用不同的消费者组，防止消息被竞争消费**

