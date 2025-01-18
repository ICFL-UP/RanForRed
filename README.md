<img src="https://github.com/ICFL-UP/RanForRed/blob/master/data/logo.png?raw=true" height="150" width="350"/>
  
 
## Ransomware Forensic Readiness (RanForRed)
This tool was designed for research in the field of Digital Forensics.


## Installation

NB: SINCE THIS IS A PROTOTYPE, WHEN TESTING MALICIOUS SAMPLES PLEASE USE THIS TOOL WITHIN A VM.


Install the dependencies:
```bash
pip install -r requirements.txt
```

Install [`openSSL`](https://wiki.openssl.org/index.php/Binaries)


## Usage
 To run the application simply run the python file ``RanForRed.py``

 ```bash
 python RanForRed.py
 ```
Create an ``.env`` file and configure the following variables
```json
TOKEN = "Bearer XXXXXXXXXXX"
IP = "http://localhost/api"
IPS = "https://localhost:8443"
API_KEY = "XXXXXXXXXXX"
API_SECRET = "XXXXXXXXXXX"
```

<img src="https://github.com/ICFL-UP/RanForRed/blob/master/data/gui.jpg?raw=true"/>

## Uploading a Cuckoo Report
<img src="https://github.com/ICFL-UP/RanForRed/blob/master/data/detect.jpg?raw=true"/>

## Testing environments
  - Windows 11
  - Windows 10


## Contributing
 
1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## Wanted
 
  - Bug reports.
  - Feedback.


## License
 
MIT License

