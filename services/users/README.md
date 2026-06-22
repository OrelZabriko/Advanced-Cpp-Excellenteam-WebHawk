# Users Service — Setup Guide

This is the user management service for WebHawk, built with Drogon (C++) and PostgreSQL.
It handles registration, login, JWT issuing, sessions, and logout.

## Prerequisites

This service runs inside **WSL (Ubuntu)** — not native Windows. Make sure you have:

- WSL with Ubuntu installed
- Drogon installed system-wide (via the course install script)
- PostgreSQL installed (comes with the course install script)
- VS Code with the WSL extension (to open and edit files from WSL)

To confirm Drogon is installed, run this in your WSL terminal:
```bash
ls /usr/local/include/drogon/drogon.h
```
If the file shows up, you're good. If not, run the course install script first:
```bash
cd ~/ExcellenceCPP2026/EXCELLENCECECPP_FinalProject/install
bash install_dragon.sh
```

---

## Step 1 — Clone the repo (inside WSL)

Open your WSL Ubuntu terminal and clone into WSL's own filesystem (not /mnt/c/...):
```bash
cd ~
git clone git@github.com:OrelZabriko/Advanced-Cpp-Excellenteam-WebHawk.git
cd Advanced-Cpp-Excellenteam-WebHawk
git checkout Benny
```

Then open in VS Code connected to WSL:
```bash
code .
```
Confirm the bottom-left corner of VS Code says **"WSL: Ubuntu"**.

---

## Step 2 — Start PostgreSQL

```bash
sudo service postgresql start
```

Enter your WSL user password when prompted.

---

## Step 3 — Create the database and set the Postgres password

Log into Postgres:
```bash
sudo -i -u postgres psql
```

Then run these SQL commands:
```sql
ALTER USER postgres WITH PASSWORD 'webhawk123';
CREATE DATABASE webhawk;
\q
```

---

## Step 4 — Create your local config.json

The config file is NOT committed to the repo (it contains credentials).
You need to create it yourself at `services/users/config.json`:

```bash
cat > ~/Advanced-Cpp-Excellenteam-WebHawk/services/users/config.json << 'EOF'
{
  "listeners": [
    {
      "address": "0.0.0.0",
      "port": 8080
    }
  ],
  "db_clients": [
    {
      "name": "default",
      "rdbms": "postgresql",
      "host": "127.0.0.1",
      "port": 5432,
      "dbname": "webhawk",
      "user": "postgres",
      "passwd": "webhawk123",
      "connection_number": 1
    }
  ]
}
