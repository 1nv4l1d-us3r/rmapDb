# rmapDb
## Implementation of rmap with MongoDb Atlas.
Running the program without any flags connects to MongoDb Atlas instance and fetches the pending scans one random (ip,port) pair from pending targets.

scans and updates the results to the database. making it effective for distributed scanning and centralized data storage.



### Requirements:

1. Scapy module

2. pymongo module
