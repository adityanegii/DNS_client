## Usage on mac: 

python3 dnsClient.py [-h] [-t TIMEOUT] [-r MAX_RETRIES] [-p PORT] [-mx] [-ns] @server name

## Usage on windows:

python dnsClient.py [-h] [-t TIMEOUT] [-r MAX_RETRIES] [-p PORT] [-mx] [-ns] @server name

## Example
```python dnsClient.py -t 5 -r 5 -mx @server 8.8.8.8 www.google.com ```

## Table
| Flag            | Description                                                                                         |
|-----------------|-----------------------------------------------------------------------------------------------------|
| `-h`            | Displays help information for the `dnsClient.py` script, showing the available options and usage.    |
| `-t TIMEOUT`    | Sets the timeout duration (in seconds) for a DNS query before considering it failed.                  |
| `-r MAX_RETRIES`| Specifies the maximum number of retry attempts in case of a failed query.                            |
| `-p PORT`       | Sets the port number to send the DNS query to.                                                      |
| `-mx`           | Requests **MX (Mail Exchange)** records, which provide information about mail servers for the domain.|
| `-ns`           | Requests **NS (Name Server)** records, which provide information about the authoritative name servers for the domain. |
| `@server`       | Specifies the DNS server to send the query to (e.g., `@8.8.8.8` for Google's public DNS server).     |
| `name`          | The domain name (hostname) you are querying DNS records for (e.g., `example.com`).                   |


## 
The following python3 version was used to implement and test the software:
    Python 3.10.7
