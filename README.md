# Damn-Vulnerable-Source-Code

There are a lots of instances when as security researchers we may need to analyse source code without a working application front end to understand the functionalities. This open source project aims to provide a platform for beginners to start reviewing source code manually without the UI.

The aim of the project is to develop intentionally vulnerable source code in various languages.

At present we are trying to build common vulnerabilities based on OWASP Top 10.

Contributors are always welcome to the project. We require more people to be a part of the same.

The first project code will be posted on the GitHub repo (Python+Flask) for a start with the readme containing an application structure and a vulnerability list so that the contributors can start building application in various languages.

Those who are interested you can make application in whichever language you are comfortable with including the vulnerabilities listed and maintaining the structure of the application and create a submission to the GitHub.

Keep an eye on this repo for the updates.


Update (19-Aug-2019)
---------------------

This section provides the pages and the purpose of the pages in the application. Eventhough we mentioned the purpose of these pages, these information are ONLY for the development purpose of the application only. The contributors can omit the submission of UI related files, images etc. Remember the objective of the project, you ONLY have visibility to Source Code. 

Naming Conventions and the page details: 
-----------------------------------------

Please keep all the pages the same name across the platforms so that the user of the project can have a comparison of the each platform and understand how the application works easily. 

index.html is the landing Page of the application , where a SignIn form and Signup Link will be available. 

signup.html will be used to create user in the application. 

homepage.html page will be used as a landing page for a valid loggged in user where additional functionalities will be present.

Mainly form to feed in PII data like credit card info / personal information. This is not a user profile page.

sl.html is secret page for the admin to login which can be used to run some of his shady stuff. 


cust_error.html - this page will act as a place to dump all the errors and exceptions.

style.css - this file is the CSS file which is used. 

app.py is the python file where the application logics are written and most of the interesting stuff happens here. 

# Vulnerabilites List: 

1. Hardcoded secrets like username and password
2. Internal IP disclosure
3. PII Data being transffered via URL
4. Insecure usgage of Random function
5. Reflected Cross Site Scripting
6. Stored Cross Site Scripting
7. Authorization bypass issues like forced browsing
8. Isecure direct object reference
9. Authentication bypass using SQL Injection
10. Sensitive Information disclosed via comments
11. Version Disclosures via Code and comments
12. Technical information revealed via stacktrace / error message

and more to come ...

Update : 04-05-2020
--------------------

At present this is a dead project due to work and other important stuff going on in life, Once I sort those out I will start working on this one. Till then stay safe and beat the crap out of COVID - 19.
