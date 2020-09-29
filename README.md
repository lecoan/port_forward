## 验收要求

- 上图中的Local Slave和Remote Listen是需要开发的程序, Local Server和Remote
Client可以使用其他软件进行测试,不需要开发.

- CHAP认证只要求3次消息交互,具体参加上图中的CHAP部分.

- Remote Listen初始只向内开启一个监听端口,向外的监听端口由Local Slave在端口监听请求消
息中指定, 如果消息中的端口参数为0,表示由Remote Listen随机选择一个端口,由端口监听应答
消息回应给Local Slave.

-为了便于验收,要求验收时按照以下格式执行,可以是单个文件执行两种模式,通过增加一个-m参数来
区分:-m slave或-m listen,其他参数要求按照以下样式编写.

Remote Listen执行

```python
python listen.py -p 8000 -u u1:p1,u2:p2
```

### 参数说明

- -p 指定向内的监听端口

- -u 指定用户名和密码,用户名和密码之间通过冒号隔开,多个用户之间用逗号隔开

### Local Slave执行

```python
python slave.py -r 127.0.0.1:8000 -u u1:p1 -p 8001 -l 127.0.0.1:8002 参数说明
```

- -r 指定Remote Listen向内的监听地址,地址和端口用冒号隔开

- -u 指定用户名和密码,用户名和密码之间通过冒号隔开

- -p 指定需要Remote Listen开启的端口,可以设置为0,由Remote Listen随机选择

- -l 指定Local Server的监听地址,地址和端口用冒号隔开

Local Server监听8002端口
Remote Client连接8001端口后,会建立与Local Server之间的双向数据流.
