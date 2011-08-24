import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.ParameterList;

public class LoginWithGoogle extends HttpServlet {
	public ConsumerManager manager;
	private String returnURL = "http://localhost:8080/OpenIDTest/openid";

	public void init() {
		this.manager = new ConsumerManager();
	}

	public void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		if ("true".equals(req.getParameter("is_request"))) {
			requestOpenId(req, res);
		} else {
			responseOpenId(req, res);
		}
	}

	public void requestOpenId(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
		try {
		    // perform discovery on the user-supplied identifier
		    List discoveries = manager.discover("https://www.google.com/accounts/o8/id");
			//List discoveries = manager.discover("http://yahoo.co.jp/");
	
		    // attempt to associate with the OpenID provider
		    // and retrieve one service endpoint for authentication
		    DiscoveryInformation discovered = manager.associate(discoveries);
	
		    // store the discovery information in the user's session for later use
		    // leave out for stateless operation / if there is no session
		    HttpSession session = req.getSession(false);
		    session.setAttribute("discovered", discovered);
	
		    // obtain a AuthRequest message to be sent to the OpenID provider
		    AuthRequest authReq = manager.authenticate(discovered, returnURL);

		    res.sendRedirect(authReq.getDestinationUrl(true));
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}

	public void responseOpenId(HttpServletRequest req, HttpServletResponse res)
			throws ServletException, IOException {
		try {
			// extract the parameters from the authentication response
			// (which comes in as a HTTP request from the OpenID provider)
			ParameterList openidResp = new ParameterList(req.getParameterMap());

			// retrieve the previously stored discovery information
			HttpSession session = req.getSession(false);
			DiscoveryInformation discovered = (DiscoveryInformation) session
					.getAttribute("discovered");

			// extract the receiving URL from the HTTP request
			StringBuffer receivingURL = req.getRequestURL();
			String queryString = req.getQueryString();
			if (queryString != null && queryString.length() > 0)
				receivingURL.append("?").append(req.getQueryString());

			// verify the response
			VerificationResult verification = manager.verify(
					receivingURL.toString(), openidResp, discovered);

			// examine the verification result and extract the verified
			// identifier
			Identifier verified = verification.getVerifiedId();

			if (verified != null) {
				// success, use the verified identifier to identify the user
				req.getRequestDispatcher("/index2.jsp").forward(req, res);
			} else {
				// OpenID authentication failed
				req.getRequestDispatcher("/index.jsp").forward(req, res);
			}
		} catch (Exception e) {
			throw new ServletException(e);
		}
	}
}
