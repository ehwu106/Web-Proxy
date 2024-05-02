# Web Proxy Server
This is a local HTTP proxy server that can accept HTTP requests from clients and convert them to HTTPS requests to the web server. It provides a secure communication channel for HTTP 1.1 with HTTPS and handles GET and HEAD requests. Additionally, the proxy server can filter requests based on an access control list and maintain an access log.

# License
[GNU Affero General Public License v3.0](LICENSE)

# Features
- Secure communication via HTTPS
- Support for HTTP 1.1
- Concurrent request handling
- Forbidden sites filtering based on access control list
- Dynamic reloading of forbidden sites file
- Logging of access details

# Help Page
Refer to the help page by typing: `./proxy -h`

# Usage
The proxy server is started with the following command:
```bash
./myproxy listen_port access_control_file access_log_file
```
- 'listen_port': The port on which the proxy server listens for incoming connections.
- 'access_control_file': Path to the file containing the list of forbidden sites, specified by domain names or IP addresses.
- 'access_log_file': Path to the access log file where details of requests will be logged.

# Example

Start the command on the Server:
```bash
./proxy 8080 ../access_control.txt access.log
```

Client:
```bash
curl -x 127.0.0.1:8080 -I www.google.com
```

The above command will give the following output to the client:
```bash
-bash-4.2$ curl -x 127.0.0.1:8080 -I www.google.com
HTTP/1.1 200 OK
Content-Type: text/html; charset=ISO-8859-1
Content-Security-Policy-Report-Only: object-src 'none';base-uri 'self';script-src 'nonce-Z-yuhzacWggMNnQaditBqQ' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws/other-hp
P3P: CP="This is not a P3P policy! See g.co/p3phelp for more info."
Date: Thu, 02 May 2024 02:15:17 GMT
Server: gws
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
Transfer-Encoding: chunked
Expires: Thu, 02 May 2024 02:15:17 GMT
Cache-Control: private
Set-Cookie: 1P_JAR=2024-05-02-02; expires=Sat, 01-Jun-2024 02:15:17 GMT; path=/; domain=.google.com; Secure
Set-Cookie: AEC=AQTF6HxniguVjA7NXwWsJ5LG_vU4JjEU0UqGOoiwyKnelysp-uRJVlJsbA; expires=Tue, 29-Oct-2024 02:15:17 GMT; path=/; domain=.google.com; Secure; HttpOnly; SameSite=lax
Set-Cookie: NID=513=bHOcyVCUyrDglLSyRzoyUQHOKIaOuPor1CKFMfnReFuZ9dMrbBs9S2KFyTtTtwnfPq6V6vZLE5BA2vKZW4hi70wq5hixk1ywnhIXbNmRc5AnPLUtHI16Il3x93e0Fk4KbiSrUOmJUcm8OKU9jyGzic64DnuWlQRiBPEu6P8QF5U; expires=Fri, 01-Nov-2024 02:15:17 GMT; path=/; domain=.google.com; HttpOnly
Alt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000
Connection: close

```

# Access Control File
The access control file contains a list of forbidden sites specified by their domains or IP addresses. When a request is received, the proxy server checks if the requested site is in the forbidden list. If so, it returns a 403 (Forbidden) error response.

Please enter the IP or domain in this format
```bash
93.184.215.14
www.facebook.com
www.youtube.com
```
