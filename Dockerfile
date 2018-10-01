FROM python:2

VOLUME /log

WORKDIR /home/pi/git/update-cloudflare
COPY update_cloudflare.py ./
COPY update_cloudflare.props.docker ./update_cloudflare.props

COPY reqs.txt ./
RUN pip install --no-cache-dir -r reqs.txt

CMD [ "python", "./update_cloudflare.py" ]
