using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace UserRegistration
{
    // Простой логгер: пишет в консоль и файл
    public static class Logger
    {
        private static readonly string LogFile = "registration.log";

        // SHA256 от пароля, всегда одинаково для одинаковых строк
        private static string Mask(string value)
        {
            if (value == null) return "[NULL]";
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(value));

            string hex = BitConverter.ToString(hash).Replace("-", "").ToLower();
            return $"[MASKED:{hex[..8]}]";
        }

        public static void Write(string login, string password, string confirm, bool ok, string error)
        {
            string maskedPwd = Mask(password);
            string maskedCnf = Mask(confirm);
            string line;

            if (ok)
                line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {login} | {maskedPwd} | {maskedCnf} | Успешная регистрация";
            else
                line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {login} | {maskedPwd} | {maskedCnf} | Ошибка: {error}";

            // В консоль
            Console.WriteLine(line);

            // В файл (дозапись)
            try
            {
                File.AppendAllText(LogFile, line + Environment.NewLine, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Не записалось в лог-файл: {ex.Message}");
            }
        }
    }

    // Валидатор
    public static class Validator
    {
        private static readonly HashSet<string> Blocked = new(StringComparer.OrdinalIgnoreCase)
        {
            "admin", "root", "moderator", "support", "administrator",
            "user", "guest", "test", "null", "undefined"
        };

        public static (bool ok, string error) Check(string login, string pwd, string pwd2)
        {
            // --- Логин ---
            if (string.IsNullOrEmpty(login))
                return (false, "Логин пустой.");

            if (Blocked.Contains(login))
                return (false, "Логин запрещён.");

            bool phone = Regex.IsMatch(login, @"^\+\d-\d{3}-\d{3}-\d{4}$");
            bool email = Regex.IsMatch(login, @"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$");
            bool simple = Regex.IsMatch(login, @"^[a-zA-Z0-9_]{5,}$");

            if (!phone && !email && !simple)
            {
                if (login.Contains('@'))
                    return (false, "Некорректный email.");
                if (login.StartsWith('+'))
                    return (false, "Некорректный телефон (+x-xxx-xxx-xxxx).");
                if (login.Length < 5)
                    return (false, "Логин-строка должна быть не менее 5 символов.");
                return (false, "Логин-строка только латиница, цифры и _.");
            }

            // --- Пароль ---
            if (string.IsNullOrEmpty(pwd))
                return (false, "Пароль пустой.");

            if (pwd.Length < 7)
                return (false, "Пароль меньше 7 символов.");

            bool up = false, low = false, dig = false, spec = false;
            foreach (char c in pwd)
            {
                if (char.IsWhiteSpace(c))
                    return (false, "Пароль не должен содержать пробелы.");

                if (char.IsDigit(c))
                    dig = true;
                else if (IsCyrillic(c))
                {
                    if (char.IsUpper(c)) up = true;
                    else low = true;
                }
                else if (!char.IsLetter(c))
                    spec = true;
                else
                    return (false, "Пароль может содержать только кириллицу, цифры и спецсимволы.");
            }

            if (!up) return (false, "Пароль должен содержать заглавную кириллическую букву.");
            if (!low) return (false, "Пароль должен содержать строчную кириллическую букву.");
            if (!dig) return (false, "Пароль должен содержать цифру.");
            if (!spec) return (false, "Пароль должен содержать спецсимвол.");

            // --- Подтверждение ---
            if (string.IsNullOrEmpty(pwd2))
                return (false, "Подтверждение пароля пустое.");

            if (pwd != pwd2)
                return (false, "Пароль и подтверждение не совпадают.");

            return (true, "");
        }

        private static bool IsCyrillic(char c)
        {
            return (c >= '\u0400' && c <= '\u04FF') ||
                   (c >= '\u0500' && c <= '\u052F') ||
                   (c >= '\u2DE0' && c <= '\u2DFF') ||
                   (c >= '\uA640' && c <= '\uA69F');
        }
    }

    class Program
    {
        static void Main()
        {
            Console.Write("Введите логин: ");
            string login = Console.ReadLine() ?? "";

            Console.Write("Введите пароль: ");
            string password = Console.ReadLine() ?? "";

            Console.Write("Подтвердите пароль: ");
            string confirm = Console.ReadLine() ?? "";

            var (success, message) = Validator.Check(login, password, confirm);

            Console.WriteLine(); // пустая строка для читаемости
            Console.WriteLine($"Результат: {(success ? "True" : "False")}");
            if (!success)
                Console.WriteLine($"Причина: {message}");

            Logger.Write(login, password, confirm, success, message);

            Console.WriteLine("\nЛог сохранён в registration.log. Нажмите любую клавишу для выхода.");
            Console.ReadKey();
        }
    }
}