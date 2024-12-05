﻿using JwtAuthApp;
using Microsoft.Data.Sqlite;

Database.Initialize();

while (true)
{
    Console.WriteLine("\n--- User Management CLI ---");
    Console.WriteLine("1. Add User");
    Console.WriteLine("2. List Users");
    Console.WriteLine("3. Login and Generate Token");
    Console.WriteLine("4. Validate Token");
    Console.WriteLine("0. Exit");
    Console.WriteLine("Select an option: ");

    var option = Console.ReadLine();

    switch (option)
    {
        case "1":
            AddUser();
            break;
        case "2":
            ListUsers();
            break;    
        case "3":
            Login();
            break;
        case "4":
            ValidateToken();
            break;
        case "0":
            Console.WriteLine("Exiting. Goodbye.");
            break;
    }
}

void AddUser()
{
    Console.Write("Enter username: ");
    var username = Console.ReadLine();

    Console.Write("Enter password: ");
    var password = Console.ReadLine();
    
    // Hash password
    var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);

    using var connection = Database.GetConnection();
    connection.Open();
    
    var insertCommand = $"""
        INSERT INTO users (username, password)
        VALUES ($username, $password);
    """;

    using var command = new SqliteCommand(insertCommand, connection);
    command.Parameters.AddWithValue("$username", username);
    command.Parameters.AddWithValue("$password", hashedPassword);

    try
    {
        command.ExecuteNonQuery();
        Console.WriteLine("User added successfully!");
    }
    catch (Exception e)
    {
        Console.WriteLine($"Error adding user: {e.Message}");
    }
}

void ListUsers()
{
    using var connection = Database.GetConnection();
    connection.Open();

    var selectCommand = "SELECT id, username FROM users";

    using var command = new SqliteCommand(selectCommand, connection);
    using var reader = command.ExecuteReader();

    Console.WriteLine("\n--- Users ---");
    while (reader.Read())
    {
        Console.WriteLine($"ID: {reader.GetInt32(0)}, Username: {reader.GetString(1)}");
    }
}

void Login()
{
    Console.Write("Enter username: ");
    var username = Console.ReadLine();

    Console.Write("Enter password: ");
    var password = Console.ReadLine();

    using var connection = Database.GetConnection();
    connection.Open();

    var query = "SELECT password FROM users WHERE username = $username";
    using var command = new SqliteCommand(query, connection);
    command.Parameters.AddWithValue("$username", username);

    var storedPassword = command.ExecuteScalar() as string;

    if (storedPassword != null && BCrypt.Net.BCrypt.Verify(password,storedPassword))
    {
        var token = JwtHelper.GenerateToken(username);
        Console.WriteLine("\nLogin successful! Here is your token:");
        Console.WriteLine(token);
    }
    else
    {
        Console.WriteLine("Invalid username or password.");
    }
}

void ValidateToken()
{
    Console.Write("Enter token: ");
    var token = Console.ReadLine();

    var principal = JwtHelper.ValidateToken(token);
    if (principal != null)
    {
        Console.WriteLine("\nToken is valid.");
        Console.WriteLine($"Username: {principal.Identity?.Name}");
    }
    else
    {
        Console.WriteLine("Invalid or expired token.");
    }
}