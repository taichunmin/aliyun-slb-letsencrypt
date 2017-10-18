FROM python:2
LABEL maintainer="taichunmin@gmail.com"

WORKDIR /root

RUN pip install --no-cache-dir \
    pipreqs \
    aliyun-python-sdk-ecs \
    aliyun-python-sdk-cdn \
    aliyun-python-sdk-rds \
    aliyun-python-sdk-cms \
    aliyun-python-sdk-mts \
    aliyun-python-sdk-vod \
    aliyun-python-sdk-live \
    aliyun-python-sdk-push \
    aliyun-python-sdk-iot \
    aliyun-python-sdk-domain \
    aliyun-python-sdk-httpdns \
    aliyun-python-sdk-green \
    aliyun-python-sdk-emr \
    aliyun-python-sdk-kms \
    aliyun-python-sdk-slb \
    aliyun-python-sdk-cloudphoto \
    aliyun-python-sdk-sas-api \
    aliyun-python-sdk-ons \
    aliyun-python-sdk-vpc \
    aliyun-python-sdk-ram \
    aliyun-python-sdk-sts

CMD ["tail", "-f", "/etc/issue"]
