 # Octopus
  Octopus是一个基于Linux系统的一个简单网络数据采集分析工具。 
  Octopus可以抓取并打印出与布尔表达式匹配的网络接口上数据包内容，也可以将数据包内容保存为pacp格式通过wireshark打开分析。
  Octopus支持针对网络层、协议、主机、网络或端口的过滤，并提供and、or、not等逻辑语句来帮助你去掉无用的信息。 
  Octopus过滤机制使用内核的BPF过滤（伯克利数据包过滤器，Berkeley Packet Filter，工作在操作系统的内核态。)
