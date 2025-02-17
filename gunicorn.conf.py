import multiprocessing

# It will set gunicorn to listen requests at localhost:8000
# bind = "localhost:8000"

# It will set gunicorn to use threads twice the number of cores and one
# one more for master thread
workers = multiprocessing.cpu_count() * 2 + 1

