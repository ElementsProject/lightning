---
title: "Tutorials"
slug: "additional-resources"
hidden: false
createdAt: "2023-02-03T08:33:51.998Z"
updatedAt: "2023-02-08T09:36:57.988Z"
---
## Writing a plugin in Python

Check out a step-by-step recipe for building a simple `helloworld.py` example plugin based on [pyln-client](https://github.com/ElementsProject/lightning/tree/master/contrib/pyln-client).


[block:tutorial-tile]
{
  "backgroundColor": "#dfb316",
  "emoji": "🦉",
  "id": "63dbd6993ef79b07b8f399be",
  "link": "https://docs.corelightning.org/v1.0/recipes/write-a-hello-world-plugin-in-python",
  "slug": "write-a-hello-world-plugin-in-python",
  "title": "Write a hello-world plugin in Python"
}
[/block]




You can also follow along the video below where Blockstream Engineer Rusty Russell walks you all the way from getting started with Core Lightning to building a plugin in Python.


[block:embed]
{
  "html": "<iframe class=\"embedly-embed\" src=\"//cdn.embedly.com/widgets/media.html?src=https%3A%2F%2Fwww.youtube.com%2Fembed%2Ffab4P3BIZxk%3Ffeature%3Doembed&display_name=YouTube&url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dfab4P3BIZxk&image=https%3A%2F%2Fi.ytimg.com%2Fvi%2Ffab4P3BIZxk%2Fhqdefault.jpg&key=7788cb384c9f4d5dbbdbeffd9fe4b92f&type=text%2Fhtml&schema=youtube\" width=\"854\" height=\"480\" scrolling=\"no\" title=\"YouTube embed\" frameborder=\"0\" allow=\"autoplay; fullscreen\" allowfullscreen=\"true\"></iframe>",
  "url": "https://www.youtube.com/watch?v=fab4P3BIZxk",
  "title": "Rusty Russell | Getting Started with c-lightning | July 2019",
  "favicon": "https://www.google.com/favicon.ico",
  "image": "https://i.ytimg.com/vi/fab4P3BIZxk/hqdefault.jpg",
  "provider": "youtube.com",
  "href": "https://www.youtube.com/watch?v=fab4P3BIZxk",
  "typeOfEmbed": "youtube"
}
[/block]




Finally, `lightningd`'s own internal [tests](https://github.com/ElementsProject/lightning/tree/master/tests/plugins) can be a useful (and most reliable) resource.

## Writing a plugin in Rust

[`cln-plugin`](https://docs.rs/cln-plugin/) is a library that facilitates the creation of plugins in Rust, with async/await support, for low-footprint plugins.

## Community built plugins

Check out this [repository](https://github.com/lightningd/plugins#plugin-builder-resources) that has a collection of actively maintained plugins as well as plugin libraries (in your favourite language) built by the community.