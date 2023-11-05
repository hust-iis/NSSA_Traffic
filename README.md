# NSSA_Traffic

## 简介

数控系统安全态势感知与分析系统的流量转发与分析模块

TrafficGathering模块负责监听某个网卡，并将其统一推送到消息队列中；TrafficAnalyzer中的每一个模块均为一个**消费者组**，负责从消息队列中获取流量信息并进行进一步处理。

## 部署

消息队列使用kafka，具体参见[官方文档](https://kafka.apache.org/documentation/)


## 注意事项

请将所有配置项写在子系统下的`config.yaml`中，**切勿硬编码在代码中**