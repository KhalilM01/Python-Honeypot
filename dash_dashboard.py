import dash  # Import the Dash framework
from dash import dcc, html  # Import the Dash core components and HTML components
from dash.dependencies import Input, Output  # Import dependencies for callbacks
import pandas as pd  # Import pandas for data manipulation
import plotly.express as px  # Import plotly.express for easy graphing

# Function to load logs from a CSV file
def load_logs(log_file):
    return pd.read_csv(log_file, parse_dates=["Timestamp"])  # Read CSV file and parse the timestamp column as datetime

# Initialize Dash
app = dash.Dash(__name__)

# Layout definition for the dashboard
app.layout = html.Div([  # Create a container div for the layout
    html.H1("SSH Honeypot Dashboard"),  # Title of the dashboard
    dcc.Graph(id="attack-frequency"),  # Graph for attack frequency over time
    dcc.Graph(id="top-usernames"),  # Graph for top attempted usernames
    dcc.Graph(id="top-passwords"),  # Graph for top attempted passwords
    dcc.Interval(id="interval-component", interval=60 * 1000, n_intervals=0)  # Interval to update every minute
])

# Define the callbacks for the interactive parts
@app.callback(
    [Output("attack-frequency", "figure"),  # Output for the attack frequency graph
     Output("top-usernames", "figure"),  # Output for the top usernames graph
     Output("top-passwords", "figure")],  # Output for the top passwords graph
    [Input("interval-component", "n_intervals")]  # Input from the interval component, triggers every minute
)
def update_dashboard(n):  # Callback function to update the dashboard
    df = load_logs("honeypot_logs.csv")  # Load the log data from the CSV file
    
    # Calculate attack frequency over time (by hour)
    attack_freq = df.set_index("Timestamp").resample("H").size().reset_index(name="Attempts")
    freq_fig = px.line(attack_freq, x="Timestamp", y="Attempts", title="SSH Attack Frequency Over Time")  # Create line chart
    
    # Get the top 10 most attempted usernames
    top_usernames = df["Username"].value_counts().head(10).reset_index()
    top_usernames.columns = ["Username", "Attempts"]  # Rename columns for clarity
    username_fig = px.bar(top_usernames, x="Username", y="Attempts", title="Top 10 Usernames Attempted")  # Create bar chart
    
    # Get the top 10 most attempted passwords
    top_passwords = df["Password"].value_counts().head(10).reset_index()
    top_passwords.columns = ["Password", "Attempts"]  # Rename columns for clarity
    password_fig = px.bar(top_passwords, x="Password", y="Attempts", title="Top 10 Passwords Attempted")  # Create bar chart
    
    return freq_fig, username_fig, password_fig  # Return the updated figures for all graphs

# Run the app in debug mode
if __name__ == "__main__":
    app.run_server(debug=True)  # Start the Dash app with debug mode enabled
