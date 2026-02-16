git clone https://github.com/risscheese/HTTP_Related_Scanner.git

cd HTTP_Related_Scanner/scanner

chmod +x header_scanner.sh  
chmod +x junk_reqScanner.py
chmod +x unsafe_scanner.sh

./{scanner} {url.txt}
