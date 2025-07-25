# 🔒 CrypticScan - Automated Penetration Testing Tool

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

---

## 🚨 **FYI:**

- **Current Status**: The project is currently **under development**. It supports **2 vulnerability tests**.
- **Upcoming Features**: Two additional penetration testing tools are slated for future releases.
- **User Interface**: The graphical user interface (GUI) is still being developed and will be connected to more pages in future updates.

---

## 🚀 **Overview**

**CrypticScan** is a sophisticated **automated penetration testing tool** designed to assess and fortify the security posture of **networks, applications, and systems**. Built by the **CyberSentinels** team, CrypticScan integrates industry-leading security tools to enable organizations and security professionals to proactively identify and mitigate vulnerabilities before malicious actors can exploit them.

### 🔑 **Key Features**:

- **Network Scanning**: Leverage **[Nmap](https://nmap.org/)** to perform deep network scans and discover open ports, services, and network information.
- **Vulnerability Assessment**: Run thorough vulnerability scans with **[OpenVAS](https://www.openvas.org/)** to identify potential security weaknesses.
- **Web Application Security Testing**: Use **[OWASP ZAP](https://www.zaproxy.org/)** to perform automated security tests on web applications.
- **Exploitation Testing**: Execute **[Metasploit](https://www.metasploit.com/)** post-exploitation tests to simulate real-world cyberattacks.
- **SQL Injection Testing**: Automate **SQL injection tests** with **[SQLmap](https://github.com/sqlmapproject/sqlmap)** to detect and exploit SQL vulnerabilities.
- **Report Generation**: Generate detailed **HTML vulnerability reports** using **Jinja2** templates for a professional presentation of your findings.

---

## 🛠️ **Technologies Used**

- **Frontend**: [Electron.js](https://www.electronjs.org/)
- **Backend**: [Flask](https://flask.palletsprojects.com/en/2.2.x/)
- **Penetration Testing Tools**:
  - [Nmap](https://nmap.org/)
  - [OpenVAS](https://www.openvas.org/)
  - [OWASP ZAP](https://www.zaproxy.org/)
  - [Metasploit](https://www.metasploit.com/)
  - [SQLmap](https://github.com/sqlmapproject/sqlmap)
- **Report Generation**: [Jinja2](https://jinja.palletsprojects.com/) and **HTML** templates

---

## ⚙️ **Installation**

### **Prerequisites**

Before setting up **CrypticScan**, ensure you have the following dependencies installed:

1. **Python** (v3.7 or later)
2. **Node.js** (v14 or later) for the Electron framework
3. **Flask** framework for backend services
4. **Penetration Testing Tools**:
   - **Nmap**, **OpenVAS**, **OWASP ZAP**, **Metasploit**, and **SQLmap**
5. **Root/Administrator Privileges**: Required to run penetration testing tools such as Metasploit and OpenVAS.

---

## 🚨 **How to Use**

### **Scanning and Vulnerability Assessment**

Follow these steps to start using **CrypticScan**:

1. **Network Scan**:
   - Input the **target IP address** or **network range** and initiate a scan using **Nmap** to discover open ports, services, and network configurations.
   
2. **Vulnerability Scan**:
   - Select the target system and run **OpenVAS** to conduct a thorough vulnerability assessment.
   
3. **Web Application Scan**:
   - Provide the **target web application's URL**, and use **OWASP ZAP** to automatically detect common web security issues.
   
4. **Metasploit Exploitation**:
   - Use **Metasploit** to exploit vulnerabilities discovered during previous scans. (Ensure **Metasploit** is properly configured).
   
5. **SQL Injection Test**:
   - Run **SQLmap** on web application endpoints to automatically test for and exploit **SQL injection** vulnerabilities.

---

## 👨‍💻 **Contributors**

The **CyberSentinels** team comprises the following contributors:

- **Bhavana Pradeep** – [GitHub Profile]
- **Faya Yasmin** – [GitHub Profile]
- **Khadeejath Mufeeda** – [GitHub Profile]
- **Fathimath Misla** – [GitHub Profile]
- **Muad Umer** – [GitHub Profile}

---

## ⚖️ **Legal Disclaimer**

**CrypticScan** is intended **solely for educational and ethical security testing purposes**. Unauthorized access to systems, networks, or applications, including penetration testing without explicit consent, is illegal and may result in severe legal consequences.

The developers of CrypticScan **disclaim all liability** for any unlawful or unauthorized activities conducted using this tool. **Users assume full responsibility** for any misuse or damage caused.

---

## 💬 **Contact**

For any questions or feedback, feel free to reach out to the project contributors through their respective GitHub profiles.

---

## 📄 **License**

This project is licensed under the **Apache License 2.0**. For detailed terms, refer to the [LICENSE](LICENSE) file.

---

## 📸 **Screenshots**

Here’s a screenshot of the **Vulnerability Scan Page** interface:

![Vulnerability Scan GUI](https://github.com/user-attachments/assets/0315a19b-7307-47fb-96b6-c33931c95801)


