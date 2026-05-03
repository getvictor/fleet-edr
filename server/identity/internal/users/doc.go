// Package users owns the `users` table that backs UI login. The store
// exposes a minimal CRUD surface (Create, Get, Count, VerifyPassword) because
// MVP has exactly one admin account; anything more is v1.1. Password hashing
// uses argon2id with the same parameter set as the enrollment token hash so a
// future consolidation into a shared `passcrypto` package is mechanical.
//
// Internal to the identity bounded context. Do not import from outside
// server/identity/.
package users
