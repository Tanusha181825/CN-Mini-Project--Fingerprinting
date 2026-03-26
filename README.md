Web Server Fingerprinting Tool

Objective:
The objective of this project is to learn about how websites communicate with each other in a network by developing a tool that will identify server software and analyze how systems communicate over different protocols.

Features:
Raw Sockets Only No high level socket libraries used
Supports both HTTP and HTTPS scanning
Ensures secure communication using SSL TLS
Extracts SSL certificate information
Includes UDP scanning (DNS and NTP services)
Resolves domain names to IP addresses
Supports multi threaded scanning
Recognizes various types of web server software
Measures response time for HTTP and HTTPS separately
Manages errors that may occur during scanning such as timeouts and hidden servers

Concept In Simple Words:
Imagine you are visiting a website When you enter a URL in your browser and click enter your system sends a request to the server and receives some information from it

This information contains some hidden data about the server

Here is what we will be doing in this project

We will be sending a request to a website
We will be receiving some information from that website
We will be analyzing that information and finding out what software is running on that server

This process is called fingerprinting

Technologies Used:
Python
Socket Programming
SSL TLS
Multi threading

How to Run:
1 Install Python
2 Run it by executing

python main.py
