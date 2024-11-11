FROM python:3.9-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建数据目录
RUN mkdir -p /app/data

# 设置环境变量
ENV FLASK_APP=app.py
ENV SQLALCHEMY_DATABASE_URI=sqlite:////app/data/pastebin.db

# 暴露端口
EXPOSE 8181

# 启动命令
CMD ["python", "app.py"] 