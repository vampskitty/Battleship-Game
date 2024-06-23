🚢 Welcome to Battleship! Ready to Conquer the Seas? 🌊

Step 1: Sign Up or Log In
New Player? Sign up using the endpoint. Don't worry; it's quick and easy!
Endpoint: POST /player/signup
Body:
{
  "username": "your_username",
  "password": "your_password"
}

Already a Sailor? Log in using the endpoint below to jump straight into the action and please keep the token that you receive in the headers.
Endpoint: POST /player/login
Body:
{
  "username": "your_username",
  "password": "your_password"
}


Step 2: Create a Game 🎮
Use this endpoint to start a new game. Upon success, you'll receive a game ID. Keep it safe for future use!
Endpoint: POST /game
Headers: Key(Authorization), Value(Bearer <your_token>)
Body:
{
  "username": "your_username",
  "password": "your_password"
}


Step 3: Join the Battle ⚔️
Join an existing game as Player 2 using the game ID with the endpoint below.
Endpoint: POST /game/:id/join
Headers: Key(Authorization), Value(Bearer <your_token>)
Body:
{
  "username": "your_username",
  "password": "your_password"
}


Step 4: Place Your Fleet 🚢
Place your ships using the endpoint. Choose wisely; strategic positioning is key! Ensure all ships are placed to start the showdown! Remember to replace the 'x' and 'y' values with your actual coordinates, and similarly, adjust the direction ('vertical' or 'horizontal') as needed.
Endpoint: POST /game/:id/place
Headers: Key(Authorization), Value(Bearer <your_token>)
Body:
{
    "placements": [
        { "x": 0, "y": 0, "direction": "vertical", "shipName": "Aircraft Carrier", "shipIndex": 0 , "size": 5},
        { "x": 0, "y": 0, "direction": "vertical", "shipName": "Battleship", "shipIndex": 1 , "size": 4},
        { "x": 0, "y": 0, "direction": "vertical", "shipName": "Cruiser", "shipIndex": 2 , "size": 3},
        { "x": 0, "y": 0, "direction": "vertical", "shipName": "Submarine", "shipIndex": 3 , "size": 3},
        { "x": 0, "y": 0, "direction": "vertical", "shipName": "Destroyer", "shipIndex": 4 , "size": 3}
    ]
}

Step 5: Take Aim and Fire! 🔥
It's your turn! Target your opponent's grid! Aim for victory: 'X' marks the spot!
Endpoint: POST /game/:id/move
Headers: Key(Authorization), Value(Bearer <your_token>)
Body:
{
  "x": 0,
  "y": 0
}


Step 6: Claim Victory
Sink all enemy ships to win! 🏆 Celebrate your triumph or prepare for a rematch!

Additional Step: View the Game Status 📊
Endpoint: GET /game/:id
Keep an eye on the game's progress and view the boards of both players after the game is over!

NOTE: Make sure to replace "your_username", "your_password" and ":id" with your actual credentials when using these endpoints.

Remember, the sea holds many surprises. Coordinate your strategies, watch your opponent's moves, and may the winds be in your favor! Happy sailing and good luck in the battle! ⚓🔥
