import mysql.connector
import asyncio

def dbConnection():
  try:
    return mysql.connector.connect(
      host="localhost",
      user="root",
      password="fuckRoot21!",
      database="mydatabase"
    )
  except mysql.connector.Error as err:
    print(f"Error connecting to MYSQL: {err}")

