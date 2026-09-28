import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class Vulnerable {

    /** VULNERABLE (SQL-001): user id concatenated directly into SQL. */
    public ResultSet findUserVulnerable(Connection conn, String userId)
            throws Exception {
        Statement statement = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = " + userId;
        return statement.executeQuery(query);
    }

    /** SAFE (SQL-001): parameterized PreparedStatement. */
    public ResultSet findUserSafe(Connection conn, String userId)
            throws Exception {
        PreparedStatement ps =
            conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        return ps.executeQuery();
    }
}
