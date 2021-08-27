<h1>Caroline's blockchain demonstrator</h1>

<p>This project was created by Karolina Podivinska as a part of her SOC work (soc.pdf). It's purpose is to demonstrate how blockchain works (or could work) implemented into electricity commerce.</p>

<p>Here is a video that introduces the whole project including the app (in Czech with English subtitles):
https://www.youtube.com/watch?v=mIEM4X9-wqY</p>

<h2>A quick installation guide</h2>
<ol>
  <li>Download all the code from this repository.</li>
  <li>Make sure you have python3 installed (not a too old version).</li>
  <li>Make sure everything from the requirements.txt file is installed (virtual environment recommended).</li>
  <li>For one-node use:
    <ol>
        <li>Choose one of the blockchain_5003.py or blockchain_5004.py files and change all the the port numbers in the file in your IDE to be the same (5003 if you have chosen the blockchain_5003.py file or 5004 if you have chosen the blockchain_5004.py file). Also, if you have chosen the blockchain_5004.py file, delete the line 29 (<code>from blockchain_5003 import users</code>), copy the user database from the blockchain_5003.py file (<code>class users</code>) and paste it to your blockchain_5004.py file after the <code>app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False</code> line.</li>
    <li>Open one tab in your browser and type localhost:5003 or localhost:5004 depending on which file you have chosen.</li>
    </ol>
  </li>
  <li>For two-nodes use:
    <ol>
  <li>Split the terminal in your IDE and run the blockchain_5003.py and blockchain_5004.py file at the same time.</li>
  <li>Open two tabs in your browser, one for localhost:5003 and the other for localhost:5004.</li>
    </ol>
  </li>
  <li>Enjoy the app!</li>
</ol>

<h2>A quick user manual</h2>
<p>Using some parts of the app is very intuitive and the app itself includes a user manual, so don't worry, download and try it to yourself!</p>
<img src="https://github.com/Caroline2/blockchain_demonstrator/blob/main/Screenshot%202021-05-24%20at%2021.52.10.png" alt="homepage of the app" title="homepage of the app">
<noindent><blockquote>
                        <b>24 May 2021 update:</b> Seems like Caroline lost touch with the file with the right offer behavior, so the offers
                        aren't being removed after someone takes advantage of them or delete them. Caroline probably won't be able to fix this up to
                        12 June 2021; so please excuse this small mistake.</blockquote><br>
  <noindent><blockquote>
                        <b>27 August 2021 update:</b> Some of the offer issues have been solved. Some features still aren't 100% functional.</blockquote>
