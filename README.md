# Octopus
  Octopus是一个基于Linux系统的一个简单网络数据采集分析工具。
  
  Octopus可以抓取并打印出与布尔表达式匹配的网络接口上数据包内容，也可以将数据包内容保存为pacp格式通过wireshark打开分析。
  
  Octopus支持针对网络层、协议、主机、网络或端口的过滤，并提供and、or、not等逻辑语句来帮助你去掉无用的信息。 
  
  Octopus过滤机制使用内核的BPF过滤（伯克利数据包过滤器，Berkeley Packet Filter，工作在操作系统的内核态。)
  
  	
  	./Octopus [ -c count ] [ -w file ] [ -v ] [ -d filter ] [ -i interface ]
    -c   收到count个计数包后退出。
  	-w   将收到的文件以pacp格式保存在file路径文件中
	-v   在命令行简单分析数据包
	-d   为程序添加数据采集过滤规则
	     比如：
		 'tcp port 80 and udp'   只抓取来自端口80的udp数据包
		 'tcp port 23 and host 192.168.1.120'   获取主机192.168.1.120接收或发出的telnet包 
  	-i   指定网卡 
  	
