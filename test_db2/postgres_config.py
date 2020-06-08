POSTGRES_URL = "127.0.0.1:5433"
POSTGRES_USER = "postgres"
POSTGRES_PW = "docker"
POSTGRES_DB = "message_store"

DB_URL = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,
                                                               pw=POSTGRES_PW,
                                                               url=POSTGRES_URL,
                                                               db=POSTGRES_DB)