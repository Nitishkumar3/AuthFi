# pip install redis

import redis

r = redis.Redis(host='127.0.0.1', port=6379, db=0)

## Hash

# Adding data to a Redis hash
r.hset('my_hash', 'key1', 'value1')

# Reading data from a Redis hash
value = r.hget('my_hash', 'key1').decode('utf-8')
print(value) 

# Updating data in a Redis hash
r.hset('my_hash', 'key1', 'new_value1')

# Deleting data from a Redis hash
r.hdel('my_hash', 'key1')