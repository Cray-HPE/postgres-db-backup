#
# MIT License
#
# (C) Copyright 2021-2022 Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
FROM artifactory.algol60.net/docker.io/library/alpine AS base

WORKDIR /usr/src/app

RUN apk add --no-cache python3 gcc python3-dev musl-dev && ln -sf python3 /usr/bin/python

# To maintain psql v12 -- pin postgresql-client and postgresql-dev
RUN echo "http://dl-cdn.alpinelinux.org/alpine/v3.12/main" >> /etc/apk/repositories
RUN apk add 'postgresql-client=12.10-r0'
RUN apk add 'postgresql-dev=12.10-r0'

RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

COPY requirements.txt constraints.txt ./
RUN pip3 install --no-cache -r requirements.txt


FROM base AS test_base

COPY requirements_test.txt .
RUN pip3 install --no-cache -r requirements_test.txt

COPY postgres_db_backup.py .


FROM test_base AS codestyle

COPY docker_codestyle_entry.sh .flake8 ./

CMD [ "./docker_codestyle_entry.sh" ]


FROM test_base AS testing

COPY docker_test_entry.sh test_postgres_db_backup.py ./

CMD [ "./docker_test_entry.sh" ]


FROM base

COPY postgres_db_backup.py .

CMD [ "python", "postgres_db_backup.py" ]
