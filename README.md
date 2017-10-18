# aliyun-slb-letsencrypt

## Install

```shell
cd /root
git clone https://github.com/taichunmin/aliyun-slb-letsencrypt.git
cp .env.example .env
pip install -U pip enum34 setuptools
pip install -r requirements.txt
chmod +x ./main.py
```

## `crontab -e`

```
0 3 * * * certbot-auto renew && env python /root/aliyun-slb-letsencrypt/main.py
```
