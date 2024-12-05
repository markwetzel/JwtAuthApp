﻿using Microsoft.Data.Sqlite;

namespace JwtAuthApp;

public static class Database
{
    private const string ConnectionString = "Data Source=users.db";

    public static void Initialize()
    {
        using var connection = new SqliteConnection(ConnectionString);
        connection.Open();

        var tableCommand = $"""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL
                    );    
        """;

        using var createTable = new SqliteCommand(tableCommand, connection);
        createTable.ExecuteNonQuery();
    }

    public static SqliteConnection GetConnection()
    {
        return new SqliteConnection(ConnectionString);
    }
}