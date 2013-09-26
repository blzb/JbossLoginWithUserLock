/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.lucasian.loginwithlock;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AccountLockedException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import javax.transaction.SystemException;
import javax.transaction.Transaction;
import org.jboss.security.ErrorCodes;
import org.jboss.security.auth.spi.DatabaseServerLoginModule;

/**
 *
 * @author Angel Pimentel
 */
public class DatabaseServerLoginModuleWithLock extends DatabaseServerLoginModule {

    protected String activeQuery;
    protected String activeUpdateQuery;
    protected String counterQuery;
    protected String counterUpdateQuery;
    protected String lastTryQuery;
    protected String lastTryUpdateQuery;

    protected int maxRetries;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
            Map<String, ?> sharedState, Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        maxRetries = Integer.parseInt((String) options.get("maxRetries"));
        activeQuery = (String) options.get("activeQuery");
        activeUpdateQuery = (String) options.get("activeUpdateQuery");
        counterQuery = (String) options.get("counterQuery");
        counterUpdateQuery = (String) options.get("counterUpdateQuery");
        lastTryQuery = (String) options.get("lastTryQuery");
        lastTryUpdateQuery = (String) options.get("lastTryUpdateQuery");

    }

    @Override
    public boolean login() throws LoginException {
        boolean result;
        HttpServletRequest request;
        Integer counter = null;
        Long timestamp = null;
        Boolean activo = null;
        String username = getUsernameAndPassword()[0];
        counter = (Integer) getValue(username, counterQuery);
        if (lastTryQuery != null) {
            timestamp = (Long) getValue(username, lastTryQuery);
        }
        activo = (Boolean) getValue(username, activeQuery);
        if (activo) {
            try {
                result = super.login();
                setValue(username, counterUpdateQuery, 0);
                if (lastTryUpdateQuery != null) {
                    timestamp = System.currentTimeMillis();
                    setValue(username, lastTryUpdateQuery, timestamp);
                }
                return result;
            } catch (FailedLoginException ex) {
                counter = counter + 1;
                setValue(username, counterUpdateQuery, counter);
                if (lastTryUpdateQuery != null) {
                    timestamp = System.currentTimeMillis();
                    setValue(username, lastTryUpdateQuery, timestamp);
                }
                if (counter >= maxRetries) {
                    setValue(username, activeUpdateQuery, false);
                }
                throw ex;
            }
        } else {
            try {
                request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
                request.setAttribute("accountlocked", true);
            } catch (PolicyContextException pce) {
                pce.printStackTrace();
            }
            throw new AccountLockedException();
        }
    }

    private Object getValue(String username, String query) throws LoginException {
        Object value = null;
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        Transaction tx = null;
        if (suspendResume) {
            //tx = TransactionDemarcationSupport.suspendAnyTransaction();
            try {
                if (tm == null) {
                    throw new IllegalStateException(ErrorCodes.NULL_VALUE + "Transaction Manager is null");
                }
                tx = tm.suspend();
            } catch (SystemException e) {
                throw new RuntimeException(e);
            }
        }

        try {
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup(dsJndiName);
            conn = ds.getConnection();
            // Get the password
            ps = conn.prepareStatement(query);
            ps.setString(1, username);
            rs = ps.executeQuery();
            if (rs.next() == false) {
                throw new FailedLoginException(ErrorCodes.PROCESSING_FAILED + "No matching username found in Principals");
            }

            value = rs.getObject(1);
        } catch (NamingException ex) {
            LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Error looking up DataSource from: " + dsJndiName);
            le.initCause(ex);
            throw le;
        } catch (SQLException ex) {
            ex.printStackTrace();
            LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Query failed");
            le.initCause(ex);
            throw le;
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                }
            }
            if (ps != null) {
                try {
                    ps.close();
                } catch (SQLException e) {
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException ex) {
                }
            }
            if (suspendResume) {
                //TransactionDemarcationSupport.resumeAnyTransaction(tx);
                try {
                    tm.resume(tx);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return value;
    }

    private void setValue(String username, String query, Object value) throws LoginException {
        Connection conn = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        Transaction tx = null;
        if (suspendResume) {
            //tx = TransactionDemarcationSupport.suspendAnyTransaction();
            try {
                if (tm == null) {
                    throw new IllegalStateException(ErrorCodes.NULL_VALUE + "Transaction Manager is null");
                }
                tx = tm.suspend();
            } catch (SystemException e) {
                throw new RuntimeException(e);
            }
        }

        try {
            InitialContext ctx = new InitialContext();
            DataSource ds = (DataSource) ctx.lookup(dsJndiName);
            conn = ds.getConnection();
            // Get the password
            ps = conn.prepareStatement(query);
            ps.setObject(1, value);
            ps.setString(2, username);
            ps.executeUpdate();
        } catch (NamingException ex) {
            LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Error looking up DataSource from: " + dsJndiName);
            le.initCause(ex);
            throw le;
        } catch (SQLException ex) {
            LoginException le = new LoginException(ErrorCodes.PROCESSING_FAILED + "Query failed");
            le.initCause(ex);
            throw le;
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException e) {
                }
            }
            if (ps != null) {
                try {
                    ps.close();
                } catch (SQLException e) {
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException ex) {
                }
            }
            if (suspendResume) {
                //TransactionDemarcationSupport.resumeAnyTransaction(tx);
                try {
                    tm.resume(tx);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}
