# Network Defender based on Spark

## 1. 文件说明
### 1.1 SparkRF 和 SparkRFonAll
判别模型的数据预处理、训练和评价文件，前后分别基于10%训练机和全部训练集。

其同名文件夹保存了训练后的对应模型。

### 1.2 Data 文件夹
存储训练集

### 1.3 DataAnalysis
分析及可视化整体数据分布。

### 1.4 RandomForest 和 GridSearchResults 文件夹
在单机情况下，基于小部分训练集对随即森林模型调参，结果记录在GridSearchResults目录下。

### 1.5 feature_analysis
分析稀疏特征。

### 1.6 utils
定义几个用于Spark DataFrame对函数，在SparkRF文件中基于Spark UserDefinedFunction使用。

## 2. Bro安装以及handle用法
根据https://docs.zeek.org/en/stable/install/install.html 上的说明我们需要以下提前安装好：
- Libpcap (http://www.tcpdump.org)
- OpenSSL libraries (http://www.openssl.org)
- BIND8 library
- Libz
- Bash (for ZeekControl)
- Python 2.6 or greater (for ZeekControl)
- CMake 2.8.12 or greater (http://www.cmake.org)
- Make
- C/C++ compiler with C++11 support (GCC 4.8+ or Clang 3.3+)
- SWIG (http://www.swig.org)
- Bison 2.5 or greater (https://www.gnu.org/software/bison/)
- Flex (lexical analyzer generator) (https://github.com/westes/flex)
- Libpcap headers (http://www.tcpdump.org)
- OpenSSL headers (http://www.openssl.org)
- zlib headers (https://zlib.net/)
- Python (https://www.python.org/)
安装步骤可以参考上述网站

再执行下指令：

```
./configure 

make

make install
```

然后把run脚本和41-feature脚本放在一起运行得到result.tmp

执行命令：`sudo ./run ens33 5`

再把result.tmp和handle.py放在同一目录运行handle.py得到result
