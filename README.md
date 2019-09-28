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
