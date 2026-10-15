import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Handles member login for the membership store.
 *
 * Members normally authenticate against the users table in the database.
 * There is also a fallback admin account, used if the database is
 * unreachable, so store staff can still get in during an outage.
 *
 * NOTE FOR STUDENTS: this file is part of the application you are analysing.
 * You are not expected to have written it — your job is to find, verify, and
 * fix the vulnerability(ies) it contains.
 */
public class LoginService {


    /**
     * Full login entry point: tries the admin fallback first, then falls
     * back to the real database-backed check.
     */
    public static boolean login(
            Connection conn,
            String username,
            String password
    ) throws SQLException {

        if (conn == null) {
            throw new SQLException(
                "Authentication database unavailable"
            );
        }

        return authenticate(conn, username, password);
    }

    /**
     * Checks the submitted credentials against the hardcoded admin fallback
     * account. Returns true only for an exact username+password match.
     */
    

    /**
     * Hashes a plaintext password before storing/comparing it against the
     * value held in the database.
     */
    public static String hashPassword(String plainPassword) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(plainPassword.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Builds the SQL statement used to look up a member by username and
     * (hashed) password. Pulled out as its own method so it can be exercised
     * directly, without needing a live database connection, to see exactly
     * what SQL text would be sent.
     */
    public static String buildLoginQuery(
            String username,
            String password
    ) {
        return "SELECT * FROM users WHERE username = ? AND password = ?";
    }

    /**
     * Full login path against the real database. Requires a live Connection
     * (not needed for the static/Semgrep analysis, or for exercising
     * buildLoginQuery directly — only relevant if you wire up an actual DB).
     */
    public static boolean authenticate(
            Connection conn,
            String username,
            String password
    ) throws SQLException {

        if (conn == null) {
            throw new SQLException(
                "Database connection required"
            );
        }

        if (username == null || password == null) {
            return false;
        }

        String hashed = hashPassword(password);

        String sql =
            "SELECT * FROM users WHERE username = ? AND password = ?";

        try (java.sql.PreparedStatement stmt =
                 conn.prepareStatement(sql)) {

            stmt.setString(1, username);
            stmt.setString(2, hashed);

            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        }
    }
    // Simple manual entry point so the query-building logic can be run/tested
    // standalone without needing a real database.
    public static void main(String[] args) {

        if (args.length < 2) {
            System.out.println(
                "Usage: java LoginService <username> <password>"
            );
            return;
        }

        System.out.println(
            "SQL template: "
            + buildLoginQuery(args[0], args[1])
        );

        System.out.println(
            "Standalone mode does not authenticate users."
        );
    }
}
