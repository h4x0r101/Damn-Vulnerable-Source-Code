Languages : C# , Python - Flask , Java , PHP

# Damn-Vulnerable-Source-Code

The idea 
---------
Presenting the Damn Vulnerable Source Code Repo. This repository acts as a location to provide intentionally vulnerable source code which would allow security professionals to horn their source code analysis skills just by reading the code. The intention of this project is to encourage indivituals to manually go through the source code to practice and learn simple source code analysis skills. 

The vulnerabilities mentioned are easy to find with your naked eyes and I would not recommend use of any scanners / tools. 

The purpose 
------------

The pupose of this repository is to provide a simple yet effective playground for cyber security professionals and anyone in general to discover potential security issues from a source code reviewer's point of view. 

Naming Conventions and the page details: - I have used the flask app as a example. 
-----------------------------------------------------------------------------------

Example : 

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

