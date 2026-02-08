# Secure Web Application & Threat Hardening

## Project Overview
This project demonstrates the design and implementation of a **secure web application** with a strong focus on **authentication, session management, and threat hardening**.  
The goal of this project is not only to build a functional web application, but also to apply **real-world security controls** commonly used to protect modern web systems against common attacks.

The application is developed using **Flask (Python)** and implements security mechanisms at the **backend level**, ensuring that protection does not rely only on the user interface.

---

## Internship Context
> **This project was built during the Cryptonic Area (Cyber Security) Virtual Internship Program.**

During this internship, I worked on understanding how real-world web applications are secured against common threats such as unauthorized access, brute-force attacks, CSRF, XSS, and insecure session handling.  
This project helped me gain practical exposure to **secure authentication flows, session hardening techniques, and defensive security design**.

---

## Key Security Features
- Secure user **registration and login system**
- Password hashing using industry-standard hashing mechanisms
- Strong password policy enforcement
- **Brute-force protection** with account lockout after multiple failed login attempts
- **CSRF protection** using token-based validation
- **Session handling and access control**
- Protection against **unauthorized direct URL access**
- Output escaping to mitigate **XSS attacks**
- Secure cookie configuration and session hardening

## Project Folder Structure

```text
Secure-Web-Application-Threat-Hardening/
├── SRC/
│   ├── app.py               # Main Flask application
│   ├── templates/           # HTML templates
│   ├── static/              # Static assets (CSS, icons)
│   └── users.db             # SQLite database
│
├── ScreenShots/
│   ├── AUTHENTICATION/      # Authentication & brute-force proof
│   ├── SESSION_HARDENING/   # Session security & access control proof
│   └── UI/                  # User interface screenshots
│
├── README.md
└── requirements.txt
```

## Setup Instructions
Follow the steps below to run the project locally:

1. **Clone the repository**
   ```bash
   git clone https://github.com/parth6213/Secure-Web-Application-Threat-Hardening.git
   cd Secure-Web-Application-Threat-Hardening
2. **Install dependencies**

     pip install -r requirements.txt


3. **Run the application**

     python SRC/app.py


4. **Access the application**

     http://127.0.0.1:5000


 ## Screenshots & Demonstration

 **The ScreenShots/ directory contains structured visual proof of implemented security controls, including:**

-> Secure registration and login flow

-> Brute-force attack protection and account lockout

-> CSRF protection validation

-> XSS protection through output escaping

-> Session handling and unauthorized access prevention

-> Secure cookie and session hardening checks

-> Clean and consistent user interface

**These screenshots demonstrate the actual backend security behavior, not just UI elements.**

## Learning Outcomes##

**Through this project, I learned:**
-> How secure authentication systems are implemented at the backend

-> The importance of password hashing and password policies

-> How brute-force attacks work and how to mitigate them

-> Why CSRF protection is critical in web applications

-> How improper session handling can lead to security vulnerabilities

-> How access control prevents unauthorized resource access

-> How to document and present security implementations professionally

## Technology Stack##

**Backend:** Python, Flask

**Database:** SQLite

**Security:** Werkzeug password hashing, CSRF tokens, session hardening

**Frontend:** HTML, CSS

## Professional Note##

This project was created as part of an academic and professional learning program and is intended to demonstrate secure coding practices and threat mitigation techniques used in real-world web applications.

The project has also been shared on LinkedIn to showcase hands-on security implementation experience.

## Author##
**Parth Joshi**
Cyber Security Intern – Cryptonic Area Virtual Internship Program
