# hackviser-CAPT-sql_injection_exam-
In the CAPT certification course in Hackviser, there is a module about sql injection. This repo will help you find answers to those questions, providing scripts that will be ready to run so that you could have the answers.
I will start off by the question 12, this is the first question where one has to interact with the machine. The question is: What is the name of the database that the web application is connected to?

Before anything else first make sure you manually configured the dns to connect to the machine. This is a very important step you shouldn't miss it at all.
sudo nano /etc/hosts then add your configuration there

You first have to find the characters in the database name, then test each character against every position to get the database name. 
Run the script named: sqli_payload_probe.py
The results of the script will proove to you this point: 
The OR-style payloads are the ones that triggered delays, which means the backend SQL fragment probably looks like:

... WHERE column LIKE '<user-input>'
and injecting ' OR ... closes that string and makes your condition evaluate.
The key points are where you see TRUE; like the line: 
      05. ' OR IF(1=1,SLEEP(6),0)-- -                                                      -> elapsed 10.00s -> TRUE (status=timeout/none)
We now have a pattern, a way to get the database name;
run the script: extract_db_name_or_style.py
Give it time and it will give you the database name.
