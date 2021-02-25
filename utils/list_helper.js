const User = require('../models/user');

const usersInDb = async () => {
  const users = await User.find({});
  return users.map(u => u.toJSON());
};

const dummy = (blogs) => {
  if (blogs !== undefined) {
    return 1;
  }
};

const totalLikes = (blogs) => {
  let likeTotal = 0;
  blogs.forEach((item) => {
    likeTotal += item.likes;
  });
  return likeTotal;
};

const favouriteBlog = (blogs) => {
  const sorted = blogs.sort( (a, b) => {
    return b.likes - a.likes;
  });
  const theFavourites = {
    author: sorted[0].author,
    title: sorted[0].title,
    likes: sorted[0].likes
  };
  return theFavourites;
};

const mostBlogs = (blogs) => {
  // copy of authors
  const authors = blogs.concat([]);
  const scores = [];
  // fill author names
  blogs.forEach((item) => {
    const howMany = authors.filter( autho => item.author === autho.author);
    // check if this author is already there
    const dublicateCheck = scores.filter( autho => item.author === autho.name);
    if (dublicateCheck.length === 0) {
      scores.push({ author: item.author, blogs: howMany.length });
    }
  });
  const sorted = scores.sort( (a, b) => {
    return b.blogs - a.blogs;
  });
  return { author: sorted[0].author, blogs: sorted[0].blogs };
};

const mostLikes = (blogs) => {
  const authors = [];
  blogs.forEach((item) => {
    const dubliCheck = authors.filter( aut => aut.author === item.author );
    if (dubliCheck.length === 0) {
      authors.push({ author: item.author, likes: item.likes });
    } else {
      authors.forEach((auts) => {
        if (auts.author === item.author) {
          auts.likes += item.likes;
        }
      });
    }
  });
  const sorted = authors.sort( (a, b) => {
    return b.likes - a.likes;
  });
  return { author: sorted[0].author, likes: sorted[0].likes };
};

module.exports = {
  dummy,
  totalLikes,
  favouriteBlog,
  mostBlogs,
  mostLikes,
  usersInDb
};
