package com.example.authserver.directory;

/** The directory could not be reached or answered unusably. Must never be treated as "user not found". */
public class DirectoryUnavailableException extends RuntimeException {

    public DirectoryUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
