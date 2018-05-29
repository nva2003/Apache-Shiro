# Apache-Shiro

# SQL sript
CREATE MEMORY TABLE PUBLIC.TESTTABLE(ID INTEGER GENERATED BY DEFAULT AS IDENTITY(START WITH 0) NOT NULL PRIMARY KEY,VALUE VARCHAR(255))
ALTER TABLE PUBLIC.TESTTABLE ALTER COLUMN ID RESTART WITH 0
CREATE MEMORY TABLE PUBLIC.USERS(USER_NAME VARCHAR(100) NOT NULL,PASSWORD VARCHAR(100) NOT NULL,CONSTRAINT USERS_PK PRIMARY KEY(USER_NAME))
CREATE MEMORY TABLE PUBLIC.USER_ROLES(USER_NAME VARCHAR(100) NOT NULL,ROLE_NAME VARCHAR(100) NOT NULL,CONSTRAINT USER_ROLES_USERS_FK FOREIGN KEY(USER_NAME) REFERENCES PUBLIC.USERS(USER_NAME))
ALTER SEQUENCE SYSTEM_LOBS.LOB_ID RESTART WITH 1
SET DATABASE DEFAULT INITIAL SCHEMA PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.SQL_IDENTIFIER TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.YES_OR_NO TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.TIME_STAMP TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.CARDINAL_NUMBER TO PUBLIC
GRANT USAGE ON DOMAIN INFORMATION_SCHEMA.CHARACTER_DATA TO PUBLIC
GRANT DBA TO SA
SET SCHEMA SYSTEM_LOBS
INSERT INTO BLOCKS VALUES(0,2147483647,0)
SET SCHEMA PUBLIC
INSERT INTO USERS VALUES('WNIO2860','WNIO2860')
INSERT INTO USERS VALUES('root','secret')
INSERT INTO USER_ROLES VALUES('root','admin')
INSERT INTO USER_ROLES VALUES('WNIO2860','group1')