# pip install pymongo

from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
db = client['demo']
collection = db["mycollection"] 

## CREATE

# Insert a single document
data = {'name': 'John Doe', 'age': 30, 'city': 'New York'}
result = collection.insert_one(data)

# Insert multiple documents
data_list = [
    {'name': 'Alice', 'age': 25, 'city': 'San Francisco'},
    {'name': 'Bob', 'age': 35, 'city': 'Los Angeles'}
]
result = collection.insert_many(data_list)

## READ

# Find a single document
document = collection.find_one({'name': 'John Doe'})
print(document)

# Find multiple documents
cursor = collection.find({'age': {'$gte': 30}}) # $gte - greater than or equal
for document in cursor:
    print(document)

## UPDATE
    
# Update a single document
collection.update_one({'name': 'John Doe'}, {'$set': {'age': 31}})

# Update multiple documents
collection.update_many({'city': 'New York'}, {'$set': {'city': 'Brooklyn'}})

## DELETE    

# Delete a single document
collection.delete_one({'name': 'John Doe'})

# Delete multiple documents
collection.delete_many({'age': {'$gte': 40}})
