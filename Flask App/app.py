from flask import Flask, render_template , request

app = Flask(__name__)

@app.route("/")
def home():
    return render_template('index.html')

# this is the function for the admin backdoor access:
@app.route("/sl", methods=["GET","POST"])
def adm_log_sec():

	key_adm = ''
	if request.method == "POST":
		key_adm = request.form['key_to_admin']
		if key_adm == "abcd":
			return render_template('administration.html')
		else:
			return render_template('index.html')
	else:
		return render_template('sl.html')

# implement login process to the app



# the main function this is going to execute like any other main function
if __name__ == "__main__":
    app.run(debug=True)
